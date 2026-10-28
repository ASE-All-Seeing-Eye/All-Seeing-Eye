"""Liest alle Geräte aus der Datenbank aus und speichert die Ausgaben als Job mit einer
Collection pro Gerät (Command pro Befehl, Konfiguration zusätzlich als Configuration).

Start (im Ordner backend):
    uv run python -m all_seeing_eye.collector.run_gns3
"""
import logging
import re
from pathlib import Path

from sqlalchemy import select

from all_seeing_eye.database.models import Device
from all_seeing_eye.database.session import SessionFactory
from all_seeing_eye.settings import settings

from all_seeing_eye.collector.collector import ConfigCollector, ConnectionSettings
from all_seeing_eye.collector.models import Credentials
from all_seeing_eye.collector.repository import CollectionRepository, to_target, vendor_key

# ---- An deine Konfiguration anpassen ----
# Die SSH-Zugangsdaten stehen in backend/.env (CISCO_SSH_USERNAME, CISCO_SSH_PASSWORD, ...)

# Nur nötig, solange der Scanner die Geräte noch nicht in die DB schreibt
LAB_DEVICES = [
    ("R1", "cisco", "10.40.1.194"),
    ("R2", "cisco", "10.40.1.195"),
    ("R3", "cisco", "10.40.1.196"),
    ("R4", "cisco", "10.40.1.197"),
    ("FortiGate-1", "fortinet", "10.40.1.198"),
]

OUTPUT_DIR = Path("gns3_output")   # zusätzlich als .txt, zum Nachschauen

# Diese Befehle werden je Hersteller ausgeführt (nur Befehle aus der Whitelist
# im Collector sind erlaubt), nicht benötigte Zeilen einfach auskommentieren.
CISCO_COMMANDS = [
    "show version",
    "show interfaces",
    "show interfaces switchport",
    "show cdp neighbors detail",
    "show lldp neighbors detail",
    "show running-config",
]
FORTINET_COMMANDS = [
    "get system status",
    "get hardware status",
    "show system interface",
    "diagnose lldprx neighbor details",
    "get system interface physical",
    "show full-configuration",           # komplette Konfiguration inkl. Standardwerte
]
COMMANDS = {"cisco": CISCO_COMMANDS, "fortinet": FORTINET_COMMANDS}
# -----------------------------------------


def load_credentials() -> dict[str, Credentials]:
    """SSH-Zugangsdaten je Hersteller aus der .env, bricht mit klarer Meldung ab, wenn etwas fehlt."""
    missing = [name for name in ("cisco_ssh_username", "cisco_ssh_password",
                                 "fortinet_ssh_username", "fortinet_ssh_password")
               if not getattr(settings, name)]
    if missing:
        raise SystemExit(f"In backend/.env fehlt: {', '.join(n.upper() for n in missing)}")
    return {
        "cisco": Credentials(settings.cisco_ssh_username, settings.cisco_ssh_password,
                             settings.cisco_ssh_secret or None),
        "fortinet": Credentials(settings.fortinet_ssh_username, settings.fortinet_ssh_password),
    }


def seed_lab_devices(session) -> None:
    known = {str(ip) for ip in session.scalars(select(Device.management_ip))}
    for name, vendor, ip in LAB_DEVICES:
        if ip not in known:
            session.add(Device(hostname=name, vendor=vendor, management_ip=ip))
    session.flush()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    credentials = load_credentials()

    with SessionFactory() as session:
        seed_lab_devices(session)
        repo = CollectionRepository(session)
        devices = {str(d.management_ip): d for d in repo.devices()}
        job = repo.create_job(target="GNS3-Lab")

        targets = [to_target(d, credentials[vendor_key(d.vendor)]) for d in devices.values()]
        collector = ConfigCollector(settings=ConnectionSettings(retries=1, retry_delay=2))
        results = collector.collect_many(targets, COMMANDS)

        print()
        collections = []
        for result in sorted(results, key=lambda r: devices[r.host].hostname or r.host):
            device = devices[result.host]
            name = device.hostname or result.host
            status = "OK" if result.success else "FEHLER" + (f" ({result.error})" if result.error else "")
            print(f"{name:11} {result.host:<14} {status} [{result.duration_s}s]")
            for cmd, raw in result.outputs.items():
                if raw.config:
                    safe_cmd = re.sub(r"\W+", "_", cmd)
                    device_dir = OUTPUT_DIR / name
                    device_dir.mkdir(parents=True, exist_ok=True)
                    (device_dir / f"{safe_cmd}.txt").write_text(raw.config, encoding="utf-8")
                elif raw.error:
                    print(f"   {cmd}: {raw.error}")
            collections.append(repo.save_result(job, device, result))

        repo.finish_job(job, collections)
        session.commit()
    print(f"\nJob {job.id} in DB gespeichert ({job.status}), Kopie in: {OUTPUT_DIR.resolve()}")


if __name__ == "__main__":
    main()
