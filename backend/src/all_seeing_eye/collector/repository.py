from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from all_seeing_eye.database.models import Collection, Command, Configuration, Device, Job

from .collector import CollectionResult
from .models import Credentials, SSHTarget

DEVICE_TYPES = {"cisco": "cisco_ios", "fortinet": "fortinet"}

# Dieser Befehl liefert die eigentliche Konfiguration und landet zusätzlich in Configuration
CONFIG_COMMANDS = {"cisco": "show running-config", "fortinet": "show full-configuration"}


def vendor_key(vendor: str | None) -> str:
    """Bringt den Hersteller aus der DB auf 'cisco' oder 'fortinet'."""
    return "fortinet" if "forti" in (vendor or "").lower() else "cisco"


def to_target(device: Device, credentials: Credentials) -> SSHTarget:
    return SSHTarget(
        device_type=DEVICE_TYPES[vendor_key(device.vendor)],
        host=str(device.management_ip),
        username=credentials.username,
        password=credentials.password,
        secret=credentials.secret,
    )


def collection_status(result: CollectionResult) -> str:
    """ok = alles geklappt, partial = verbunden, aber einzelne Befehle fehlgeschlagen, failed = keine Verbindung."""
    if result.error:
        return "failed"
    return "ok" if result.success else "partial"


class CollectionRepository:
    def __init__(self, session: Session):
        self.session = session

    def devices(self) -> list[Device]:
        return list(self.session.scalars(select(Device)))

    def create_job(self, target: str) -> Job:
        job = Job(target=target, status="running")
        self.session.add(job)
        self.session.flush()
        return job

    def save_result(self, job: Job, device: Device, result: CollectionResult) -> Collection:
        """Speichert einen Lauf als Collection mit einer Command-Zeile pro Befehl
        und der Konfiguration (show running-config bzw. show) als Configuration."""
        if result.hostname:
            device.hostname = result.hostname

        collection = Collection(device=device, job=job, status=collection_status(result),
                                error_message=result.error)
        self.session.add(collection)

        for name, raw in result.outputs.items():
            collection.commands.append(Command(
                name=name,
                output=raw.config,
                parse_status="error" if raw.error else "pending",
                error_message=raw.error,
            ))

        config = result.outputs.get(CONFIG_COMMANDS[vendor_key(device.vendor)])
        if config and config.config:
            collection.configuration = Configuration(content=config.config, parse_status="pending")

        self.session.flush()
        return collection

    def finish_job(self, job: Job, collections: list[Collection]) -> None:
        failed = [c for c in collections if c.status == "failed"]
        job.status = "failed" if collections and len(failed) == len(collections) else "done"
        job.finished_at = datetime.now(timezone.utc)
        if failed:
            job.error_message = f"{len(failed)} von {len(collections)} Geräten nicht erreichbar"
