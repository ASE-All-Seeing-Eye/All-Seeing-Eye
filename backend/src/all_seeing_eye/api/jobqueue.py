import logging
import threading

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from all_seeing_eye.analysis.analyzer import analyze_collection
from all_seeing_eye.collector.collector import ConfigCollector, ConnectionSettings
from all_seeing_eye.collector.repository import CollectionRepository, to_target, vendor_key
from all_seeing_eye.collector.run_gns3 import COMMANDS, load_credentials
from all_seeing_eye.constants import Status
from all_seeing_eye.database import repository
from all_seeing_eye.database.models import Job
from all_seeing_eye.database.session import SessionFactory
from all_seeing_eye.parser.ingest import process_collection, resolve_connections
from all_seeing_eye.scanner.networkscanner import DeviceProbe, NetworkScanner, TargetParser

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/jobqueue", tags=["Job-Queue"])

lauf = {"job_id": None, "schritt": None}
sperre = threading.Lock()
LAB_GERAETE = [
    ("FGT-01", "fortinet", "10.50.20.1"),
    ("N9K-01", "cisco", "10.50.10.11"),
    ("N9K-02", "cisco", "10.50.10.12"),
    ("CAT-01", "cisco", "10.50.10.21"),
    ("CAT-02", "cisco", "10.50.10.22"),
]

class StartAnfrage(BaseModel):
    ziel: str | None = None


@router.post("/start")
def job_starten(anfrage: StartAnfrage):
    if not sperre.acquire(blocking=False):
        raise HTTPException(status_code=409, detail=f"Job {lauf['job_id']} läuft noch")
    try:
        job_id = repository.create_job(anfrage.ziel or "Alle bekannten Geräte")
    except Exception:
        sperre.release()
        raise
    lauf["job_id"] = job_id
    threading.Thread(target=ablauf, args=(job_id, anfrage.ziel), daemon=True).start()
    return {"job_id": job_id}


@router.get("/status")
def job_status():
    return {"laeuft": lauf["job_id"] is not None, "job_id": lauf["job_id"], "schritt": lauf["schritt"]}


def ablauf(job_id: int, ziel: str | None) -> None:
    probleme = []
    try:
        repository.set_job_status(job_id, Status.RUNNING)

        if ziel:
            lauf["schritt"] = "Netzwerk wird gescannt"
            NetworkScanner(DeviceProbe(), TargetParser()).scan(job_id)

        lauf["schritt"] = "Konfigurationen werden von den Geräten geholt"
        collection_ids, geraete_fehler = sammeln(job_id)
        probleme.extend(geraete_fehler)

        lauf["schritt"] = "Ausgaben werden ausgewertet"
        for collection_id in collection_ids:
            try:
                process_collection(collection_id)
            except Exception as e:
                logger.exception("Parser: Collection %s fehlgeschlagen", collection_id)
                probleme.append(f"Parser Collection {collection_id}: {e}")
        resolve_connections()

        lauf["schritt"] = "Sicherheitsanalyse läuft"
        for collection_id in collection_ids:
            try:
                analyze_collection(collection_id)
            except Exception as e:
                logger.exception("Analyse: Collection %s fehlgeschlagen", collection_id)
                probleme.append(f"Analyse Collection {collection_id}: {e}")

        status = Status.PARTIAL if probleme else Status.OK
        repository.set_job_status(job_id, status, "; ".join(probleme) or None)
    except (Exception, SystemExit) as e:
        logger.exception("Job %s abgebrochen", job_id)
        repository.set_job_status(job_id, Status.FAILED, str(e) or type(e).__name__)
    finally:
        lauf["job_id"] = None
        lauf["schritt"] = None
        sperre.release()


def sammeln(job_id: int) -> tuple[list[int], list[str]]:
    for name, hersteller, ip in LAB_GERAETE:
        repository.create_or_update_device(management_ip=ip, hostname=name, vendor=hersteller)    
    credentials = load_credentials()
    with SessionFactory() as session:
        repo = CollectionRepository(session)
        job = session.get(Job, job_id)
        lab_ips = {ip for _, _, ip in LAB_GERAETE}
        geraete = {str(d.management_ip): d for d in repo.devices() if str(d.management_ip) in lab_ips}
        if not geraete:
            raise ValueError("Keine Geräte in der Datenbank")

        ziele = [to_target(d, credentials[vendor_key(d.vendor)]) for d in geraete.values()]
        collector = ConfigCollector(max_workers=1, settings=ConnectionSettings(retries=1, retry_delay=2))
        ergebnisse = collector.collect_many(ziele, COMMANDS)

        collections = [repo.save_result(job, geraete[e.host], e) for e in ergebnisse]
        session.commit()
        erfolgreich = [c.id for c in collections if c.status != "failed"]
        fehler = [f"{c.device.hostname or c.device.management_ip}: {c.error_message}"
                  for c in collections if c.status == "failed"]
        return erfolgreich, fehler