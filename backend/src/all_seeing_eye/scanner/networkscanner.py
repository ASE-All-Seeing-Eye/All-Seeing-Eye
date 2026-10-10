from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass


@dataclass
class Device:
    ip: str
    hostname: str
    vendor: str
    model: str
    os_version: str



class TcpProbe:

    def __init__(self, timeout: float) -> None:
        self.timeout = timeout

    def check(self, ip: str, port: int) -> str:
        try:
            with socket.create_connection((ip, port), timeout=self.timeout):
                return "open"
        except (ConnectionRefusedError, TimeoutError):
            return "closed"


@dataclass()
class PortResult:
    port: int
    transport: int
    state: bool
    service: str
    banner: str


class TargetParser:
    def __init__(self) -> None:

    @staticmethod
    def parse_targets(self, value: str) -> list[str]:
        value = value.strip()

        if "/" in value:
            network = ipaddress.IPv4Network(value, strict=False)
            return [str(address) for address in network.hosts()]

        elif "-" in value:
            start_text, end_text = value.split("-", 1)

            start_ip = ipaddress.IPv4Address(start_text.strip())
            prefix, start_number = str(start_ip).rsplit(".", 1)

            start_number = int(start_number)
            end_number = int(end_text.strip())

            if 0 <= end_number <= 255 and start_number <= end_number:
                return [f"{prefix}.{i}" for i in range(start_number, end_number+1)]
            else:
                raise ValueError("False IP input!")

        else:
            address = ipaddress.IPv4Address(value)
            return [str(address)]


class DeviceProbe:

    def __init__(self, timeout: float = 1.0):
            self.timeout = timeout
            self.ports = [22,23,80,443,445,830,3389]


    def check_tcp_port(self, ip: str, port: int) -> str:
        try:
            with socket.create_connection((ip,port), timeout=self.timeout):
                return "open"
        except (ConnectionRefusedError, TimeoutError):
                return "closed"

    def check_ports(self, ip: str) -> dict[int, str]:
        results = {}

        for port in self.ports:
            results[port] = self.check_tcp_port(ip, port)
        return results

    def resolve_hostname(self, ip: str) -> str | None:
        try:
           hostname, aliases, addresses = socket.gethostbyaddr(ip)
           return hostname
        except socket.herror:
            return None