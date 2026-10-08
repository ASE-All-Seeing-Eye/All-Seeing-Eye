"""Liest die vier GNS3-Router (und die FortiGate) aus und speichert die Ausgaben.

Zwei Modi (siehe USE_CONSOLE):
  True  = nur Router nötig: Telnet über die GNS3-Console (nur fürs Lab)
  False = SSH über die Management-IP (braucht Cloud + Switch; nur hier wird auch die FortiGate abgefragt)

Start (im Ordner mit collector.py und models.py):
    python "Run gns3.py"
"""
import logging
import re
from pathlib import Path

try:
    from .collector import ConfigCollector, ConnectionSettings
    from .models import Device
except ImportError:  # direkt aus dem Ordner gestartet
    from collector import ConfigCollector, ConnectionSettings
    from models import Device

# ---- An deine Konfiguration anpassen ----
USE_CONSOLE = False

# Modus Console: GNS3-VM und Console-Ports (rechts in "Topology Summary")
GNS3_VM = "192.168.83.128"
CONSOLE_PORTS = {"Router1": 5005, "Router2": 5024, "Router3": 5001, "Router4": 5003}

# Modus SSH: Management-IPs und Zugangsdaten
SSH_IPS = {"Router1": "192.168.83.11", "Router2": "192.168.83.12",
           "Router3": "192.168.83.13", "Router4": "192.168.83.14"}
USERNAME = "admin"
PASSWORD = "cisco123"

SECRET = "cisco123"   # Enable-Passwort (nur Cisco)

# FortiGate (nur im SSH-Modus): Management-IP und Zugangsdaten
FORTIGATES = {"FortiGate1": "192.168.83.20"}
FORTIGATE_USER = "admin"
FORTIGATE_PASSWORD = "admin"

OUTPUT_DIR = Path("gns3_output")

# Diese Befehle werden je Hersteller ausgeführt (nur Befehle aus der Whitelist
# im Collector sind erlaubt). Über die Console dauert jeder Befehl ein paar Sekunden,
# nicht benötigte Zeilen einfach auskommentieren.
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


def build_devices() -> dict[tuple[str, int], tuple[str, Device]]:
    """Gibt {(host, port): (name, Device)} zurück."""
    devices = {}
    for name in CONSOLE_PORTS:
        if USE_CONSOLE:
            dev = Device("cisco_ios_telnet", GNS3_VM, None, None, SECRET, CONSOLE_PORTS[name])
        else:
            dev = Device("cisco_ios", SSH_IPS[name], USERNAME, PASSWORD, SECRET)
        devices[(dev.host, dev.port)] = (name, dev)
    if not USE_CONSOLE:
        for name, ip in FORTIGATES.items():
            dev = Device("fortinet", ip, FORTIGATE_USER, FORTIGATE_PASSWORD)
            devices[(dev.host, dev.port)] = (name, dev)
    return devices


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")

    devices = build_devices()
    settings = ConnectionSettings(retries=1, retry_delay=2, allow_telnet=USE_CONSOLE)
    collector = ConfigCollector(settings=settings)
    results = collector.collect_many([dev for _, dev in devices.values()], COMMANDS)

    OUTPUT_DIR.mkdir(exist_ok=True)
    print()
    for result in sorted(results, key=lambda r: devices[(r.host, r.port)][0]):
        name = devices[(result.host, result.port)][0]
        status = "OK" if result.success else "FEHLER" + (f" ({result.error})" if result.error else "")
        print(f"{name:11} {result.host}:{result.port:<6} {result.hostname or '-':10} {status} [{result.duration_s}s]")
        for cmd, raw in result.outputs.items():
            if raw.config:
                safe_cmd = re.sub(r"\W+", "_", cmd)
                router_dir = OUTPUT_DIR / name
                router_dir.mkdir(parents=True, exist_ok=True)
                (router_dir / f"{safe_cmd}.txt").write_text(raw.config, encoding="utf-8")
            elif raw.error:
                print(f"   {cmd}: {raw.error}")
    print(f"\nAusgaben gespeichert in: {OUTPUT_DIR.resolve()}")


if __name__ == "__main__":
    main()