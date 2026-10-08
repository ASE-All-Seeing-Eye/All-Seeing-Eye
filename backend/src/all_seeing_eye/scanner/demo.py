import argparse
import json
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from networkscanner import (
    NetworkScanner,
    SshBannerProbe,
    TcpProbe,
    parse_targets,
    parse_ports,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Live-Demo des ASE Network Scanners"
    )
    parser.add_argument(
        "network",
        help="IPv4, CIDR oder Bereich, z. B. 10.40.1.193-197",
    )
    parser.add_argument(
        "--ports",
        type=parse_ports,
        default=parse_ports("22,23,80,443,445,830,3389"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("scan_result.json"),
    )
    args = parser.parse_args()
    try:
        targets = parse_targets(args.network)
    except argparse.ArgumentTypeError as error:
        parser.error(str(error))
    scanner = NetworkScanner(
        tcp=TcpProbe(timeout=0.5),
        ports=args.ports,
        workers=16,
        ssh=SshBannerProbe(timeout=2.0),
    )

    started_at = datetime.now(timezone.utc).isoformat()

    print(f"Zielbereich: {args.network}")
    print(f"Zu prüfende IP-Adressen: {len(targets)}")
    print(f"TCP-Ports: {args.ports}")
    print("Scan laeuft ...", flush=True)

    start = time.perf_counter()
    devices = scanner.scan(targets)
    duration = time.perf_counter() - start

    print()
    print(f"{'IP-Adresse':<16} {'Offene TCP-Ports':<28} SSH-Banner")
    print("-" * 90)

    for device in devices:
        ports = ", ".join(map(str, device.open_ports)) or "-"
        banner = (
            ascii(device.ssh_banner)
            if device.ssh_banner is not None
            else "nicht erhalten"
        )
        print(f"{device.ip:<16} {ports:<28} {banner}")

    if not devices:
        print("Keine antwortenden IP-Adressen erkannt.")

    print()
    print(f"Antwortende IP-Adressen: {len(devices)}")
    print(f"Dauer: {duration:.2f} Sekunden")
    print(f"Erfasste Fehler: {len(scanner.errors)}")

    if scanner.errors:
        print("\nFehler:")
        for error in scanner.errors:
            print(f"- {ascii(error)}")

    payload = {
        "started_at_utc": started_at,
        "target": args.network,
        "target_addresses": [str(ip) for ip in targets],
        "ports": args.ports,
        "duration_seconds": round(duration, 3),
        "detected_address_count": len(devices),
        "status": "completed_with_errors" if scanner.errors else "completed",
        "devices": [asdict(device) for device in devices],
        "errors": scanner.errors,
    }

    try:
        args.output.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError as error:
        print(f"\nExport fehlgeschlagen: {error}")
        return 1

    print(f"\nErgebnis gespeichert: {args.output.resolve()}")
    return 1 if scanner.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())