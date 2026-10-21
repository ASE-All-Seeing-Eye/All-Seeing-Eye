"""Liest alle Geräte aus der Datenbank aus und speichert die Ausgaben als Configuration.

Start (im Ordner backend):
    uv run python -m all_seeing_eye.collector.run_gns3
"""
import logging
import re
from pathlib import Path

from sqlalchemy import select

from all_seeing_eye.database.models import Device
from all_seeing_eye.database.session import SessionFactory

from .collector import ConfigCollector, ConnectionSettings
from .models import Credentials
from .repository import CollectionRepository, to_target, vendor_key

# ---- An deine Konfiguration anpassen ----
CREDENTIALS = {   # Lab-Passwörter, nicht ins Repository committen
    "cisco": Credentials("automation", "Gns3Lab2026"),
    "fortinet": Credentials("admin", "admin"),
}

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
    "show running-config",
    "show startup-config",
    "show version",
    "show inventory",
    "show clock",
    "show users",
    "show logging",
    "show ip ssh",
    "show ip interface brief",
    "show interfaces description",
    "show ip route",
    "show ip protocols",
    "show ip ospf neighbor",
    "show access-lists",
    "show cdp neighbors",
    "show cdp neighbors detail",
]
FORTINET_COMMANDS = [
    "get system status",
    "show",                              # Konfiguration (nur Abweichungen vom Standard)
    "get system interface physical",
    "get router info routing-table all",
    "get router info ospf neighbor",
    "get system arp",
    "get system admin list",
    "get system performance status",
]
COMMANDS = {"cisco": CISCO_COMMANDS, "fortinet": FORTINET_COMMANDS}
# -----------------------------------------


def seed_lab_devices(session) -> None:
    known = {str(ip) for ip in session.scalars(select(Device.management_ip))}
    for name, vendor, ip in LAB_DEVICES:
        if ip not in known:
            session.add(Device(hostname=name, vendor=vendor, os_version="", management_ip=ip))
    session.flush()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")

    with SessionFactory() as session:
        seed_lab_devices(session)
        repo = CollectionRepository(session)
        devices = {str(d.management_ip): d for d in repo.devices()}

        targets = [to_target(d, CREDENTIALS[vendor_key(d.vendor)]) for d in devices.values()]
        collector = ConfigCollector(settings=ConnectionSettings(retries=1, retry_delay=2))
        results = collector.collect_many(targets, COMMANDS)

        print()
        for result in sorted(results, key=lambda r: devices[r.host].hostname):
            device = devices[result.host]
            status = "OK" if result.success else "FEHLER" + (f" ({result.error})" if result.error else "")
            print(f"{device.hostname:11} {result.host:<14} {status} [{result.duration_s}s]")
            for cmd, raw in result.outputs.items():
                if raw.config:
                    safe_cmd = re.sub(r"\W+", "_", cmd)
                    device_dir = OUTPUT_DIR / device.hostname
                    device_dir.mkdir(parents=True, exist_ok=True)
                    (device_dir / f"{safe_cmd}.txt").write_text(raw.config, encoding="utf-8")
                elif raw.error:
                    print(f"   {cmd}: {raw.error}")
            repo.save_result(device, result)

        session.commit()
    print(f"\nIn DB gespeichert, Kopie in: {OUTPUT_DIR.resolve()}")


if __name__ == "__main__":
    main()
