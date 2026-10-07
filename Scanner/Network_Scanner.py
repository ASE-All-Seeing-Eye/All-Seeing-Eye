from __future__ import annotations

import argparse
import errno
import ipaddress
import math
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field


@dataclass
class Device:
    """Eine beobachtete IP ist noch keine dauerhafte Geraeteidentitaet."""

    ip: str
    open_ports: list[int] = field(default_factory=list)
    refused_ports: list[int] = field(default_factory=list)
    ssh_banner: str | None = None

    @property
    def detected(self) -> bool:
        # Auch eine aktiv abgelehnte TCP-Verbindung ist ein Lebenszeichen.
        return bool(self.open_ports or self.refused_ports)


class TcpProbe:
    """Prueft TCP mit einem normalen Verbindungsaufbau und Zeitlimit."""

    def __init__(self, timeout: float) -> None:
        self.timeout = timeout

    def check(self, ip: str, port: int) -> str:
        try:
            with socket.create_connection((ip, port), timeout=self.timeout):
                return "open"
        except OSError as error:
            codes = {error.errno, getattr(error, "winerror", None)}
            if codes & {errno.EACCES, errno.EPERM, 10013}:
                raise PermissionError(
                    "TCP-Zugriff blockiert. Lokale Netzwerk- oder "
                    "Sicherheitsrichtlinien fuer Python pruefen."
                ) from error
            if codes & {errno.ECONNREFUSED, 10061}:
                return "refused"
            if isinstance(error, TimeoutError) or codes & {
                errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH,
                10060, 10065, 10051,
            }:
                return "no_response"
            # Lokale Fehler nicht als vermeintlich abwesende Geraete verbergen.
            raise

class SshBannerProbe:
    "Liesst die SSH-Identifikationszeile aus."
    def __init__(self, timeout: float) -> None:
        self.timeout = timeout

    def read_banner(self, ip: str, port: int) -> str | None:
        deadline = time.monotonic() + self.timeout
        try:
            with socket.create_connection((ip,port), timeout=self.timeout) as connection:
                buffer = b""
                received_bytes = 0
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return None
                    connection.settimeout(remaining)

                    data = connection.recv(1024)
                    received_bytes += len(data)
                    if received_bytes > 8192:
                        return None

                    if not data:
                        return None

                    buffer += data
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        line = line.rstrip(b"\r")
                        if line.startswith(b"SSH-"):
                            return line.decode("ascii", errors="replace")
        except (TimeoutError, ConnectionRefusedError, ConnectionResetError):
            return None


class NetworkScanner:
    """Koordiniert die Pruefungen; Komponenten sind im Test austauschbar."""

    def __init__(
            self,
            tcp: TcpProbe,
            ports: list[int],
            workers: int = 24,
    ) -> None:
        self.tcp = tcp
        self.ports = ports
        self.workers = workers

    def scan_host(self, ip: str) -> Device:
        device = Device(ip=ip)
        for port in self.ports:
            status = self.tcp.check(ip, port)
            if status == "open":
                device.open_ports.append(port)
            elif status == "refused":
                device.refused_ports.append(port)
        return device

    def scan(self, network: ipaddress.IPv4Network) -> list[Device]:
        """Liefert erkannte Hosts ohne Konsolenausgabe; Fehler gehen an den Aufrufer."""
        devices = []
        addresses = list(network.hosts())
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            tasks = [
                executor.submit(self.scan_host, str(ip))
                for ip in addresses
            ]
            for task in as_completed(tasks):
                device = task.result()
                if device.detected:
                    devices.append(device)
        return sorted(devices, key=lambda device: ipaddress.IPv4Address(device.ip))


def parse_network(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Ungueltiges IPv4-Netz.") from error
    private_ranges = [
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    ]
    if not isinstance(network, ipaddress.IPv4Network):
        raise argparse.ArgumentTypeError("Diese erste Version unterstuetzt nur IPv4.")
    if not any(network.subnet_of(block) for block in private_ranges):
        raise argparse.ArgumentTypeError("Bitte ein privates RFC1918-Testnetz angeben.")
    if network.prefixlen < 24:
        raise argparse.ArgumentTypeError(
            "Diese Startversion erlaubt hoechstens /24 (256 Adressen). "
            "Waehle ein kleineres Testnetz oder eine einzelne IP mit /32."
        )
    return network


def parse_ports(value: str) -> list[int]:
    try:
        ports = sorted(set(int(part.strip()) for part in value.split(",")))
    except ValueError as error:
        raise argparse.ArgumentTypeError("Ports als Zahlen mit Kommas angeben.") from error
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise argparse.ArgumentTypeError("Ports muessen zwischen 1 und 65535 liegen.")
    return ports



def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("network", type=parse_network, help="z. B. 192.168.10.0/24")
    parser.add_argument(
        "--ports", type=parse_ports, default=parse_ports("22,23,80,443,445,830,3389"),
        help="TCP-Ports, Standard: 22,23,80,443,445,830,3389",
    )
    parser.add_argument("--timeout", type=float, default=0.5, help="Zeitlimit je Probe in Sekunden")
    parser.add_argument("--workers", type=int, default=24, help="Gleichzeitig untersuchte Hosts")
    args = parser.parse_args()

    if not math.isfinite(args.timeout) or not 0.1 <= args.timeout <= 10:
        parser.error("--timeout muss zwischen 0.1 und 10 Sekunden liegen.")
    if not 1 <= args.workers <= 64:
        parser.error("--workers muss zwischen 1 und 64 liegen.")

    scanner = NetworkScanner(
        TcpProbe(args.timeout), args.ports, args.workers
    )
    try:
        scanner.scan(args.network)
    except OSError:
        return 1
    return 0



if __name__ == "__main__":
    raise SystemExit(main())
