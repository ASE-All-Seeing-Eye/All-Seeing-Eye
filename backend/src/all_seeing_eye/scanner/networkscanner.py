from __future__ import annotations

import errno
import struct
import time
import ipaddress
import socket

from all_seeing_eye.database import repository



class TargetParser:

    def parse_job_targets(self, job_id: int) -> list[str]:

        job = repository.get_job(job_id)
        if job is None:
            raise ValueError(f"Job {job_id} existiert nicht")
        return self.parse_targets(job["target"])

    def parse_targets(self, value: str) -> list[str]:
        value = value.strip()

        if "/" in value:
            network = ipaddress.IPv4Network(value, strict=False)
            return [str(address) for address in network.hosts()]

        if "-" in value:
            start_text, end_text = value.split("-", 1)
            start_ip = ipaddress.IPv4Address(start_text.strip())
            end_text = end_text.strip()

            if end_text.isascii() and end_text.isdigit():
                prefix = str(start_ip).rsplit(".", 1)[0]
                end_text = f"{prefix}.{end_text}"
            end_ip = ipaddress.IPv4Address(end_text)

            if start_ip > end_ip:
                raise ValueError("Die Start-IP darf nicht nach der End-IP liegen.")
            return [
                str(ipaddress.IPv4Address(address))
                for address in range(int(start_ip), int(end_ip) + 1)
            ]

        return [str(ipaddress.IPv4Address(value))]


class DeviceProbe:

    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
        self.tcp_ports = [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143,
                          144, 179, 199, 389, 427, 443, 444, 445,
                          465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027,
                          1028, 1029, 1110, 1433, 1720, 1723,
                          1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
                          5051, 5060, 5101, 5190, 5357, 5432,
                          5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
                          9100, 9999, 10000, 32768, 49152,
                          49153, 49154, 49155, 49156, 49157]
        self.udp_ports = [53, 123, 137, 161, 1900]

    def check_tcp_port(self, ip: str, port: int) -> str:
        try:
            with socket.create_connection((ip, port), timeout=self.timeout):
                return "open"
        except ConnectionRefusedError:
            return "refused"
        except TimeoutError:
            return "closed"

    def check_tcp_ports(self, ip: str) -> dict[int, str]:
        result = {}
        for port in self.tcp_ports:
            result[port] = self.check_tcp_port(ip, port)

        return result

    def build_udp_payload(self, port: int) -> bytes:
        if port == 53:
            return (
                b"\x12\x34\x01\x00"
                b"\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x07example\x03com\x00"
                b"\x00\x01\x00\x01"
            )

        if port == 123:
            timestamp = time.time() + 2_208_988_800
            seconds = int(timestamp)
            fraction = int((timestamp - seconds) * (1 << 32))

            return (
                    b"\x23"
                    + b"\x00" * 39
                    + struct.pack("!II", seconds & 0xFFFFFFFF, fraction)
            )

        if port == 137:
            return (
                    b"\x12\x34\x00\x00"
                    b"\x00\x01\x00\x00\x00\x00\x00\x00"
                    b"\x20"
                    + b"CK"
                    + b"A" * 30
                    + b"\x00\x00\x21\x00\x01"
            )

        if port == 161:
            return bytes.fromhex(
                "30 26"
                "02 01 01"
                "04 06 70 75 62 6c 69 63"
                "a0 19"
                "02 01 01"
                "02 01 00"
                "02 01 00"
                "30 0e"
                "30 0c"
                "06 08 2b 06 01 02 01 01 01 00"
                "05 00"
            )

        if port == 1900:
            return (
                b"M-SEARCH * HTTP/1.1\r\n"
                b"HOST: 239.255.255.250:1900\r\n"
                b'MAN: "ssdp:discover"\r\n'
                b"MX: 1\r\n"
                b"ST: ssdp:all\r\n"
                b"\r\n"
            )

        raise ValueError(f"Kein UDP-Payload für Port {port} definiert")

    def check_udp_port(self, ip: str, port: int) -> str:
        payload = self.build_udp_payload(port)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            timeout = max(self.timeout, 2.0) if port == 1900 else self.timeout
            sock.settimeout(timeout)

            try:
                if port == 1900:
                    sock.sendto(payload, (ip, port))
                    deadline = time.monotonic() + timeout

                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            return "open_or_filtered"

                        sock.settimeout(remaining)
                        response, sender = sock.recvfrom(65535)
                        if (
                                sender[0] == ip
                                and response.startswith(b"HTTP/1.1 200")
                        ):
                            return "open"
                else:
                    sock.connect((ip, port))
                    sock.send(payload)
                    response = sock.recv(65535)
                    return "open"

            except TimeoutError:
                return "closed"
            except OSError as error:
                if (
                        error.errno == errno.ECONNREFUSED
                        or getattr(error, "winerror", None) in {10061, 10054}
                ):
                    return "closed"
                raise

    def check_udp_ports(self, ip: str) -> dict[int, str]:
        results = {}

        for port in self.udp_ports:
            results[port] = self.check_udp_port(ip, port)

        return results


class NetworkScanner:
    def __init__(self, probe: DeviceProbe, parser: TargetParser):
        self.probe = probe
        self.parser = parser

    def scan(self, job_id: int) -> int:
        targets = self.parser.parse_job_targets(job_id)
        scan_id = repository.create_scan(job_id)

        try:
            for ip in targets:
                self.scan_host(scan_id, ip)
        except Exception:
            repository.finish_scan(scan_id, "failed")
            raise
        else:
            repository.finish_scan(scan_id, "completed")

        return scan_id

    def scan_host(self, scan_id: int, ip: str) -> int | None:
        tcp_results = self.probe.check_tcp_ports(ip)
        udp_results = self.probe.check_udp_ports(ip)

        tcp_answered = any(
            status in {"open", "refused"}
            for status in tcp_results.values()
        )
        udp_answered = any(
            status == "open"
            for status in udp_results.values()
        )

        if not (tcp_answered or udp_answered):
            return None

        open_tcp_ports = [
            port for port, status in tcp_results.items()
            if status == "open"
        ]

        open_udp_ports = [
            port for port, status in udp_results.items()
            if status == "open"
        ]

        device_id = repository.create_or_update_device(ip)

        scan_host_id = repository.add_scan_host(
            scan_id=scan_id,
            ip_address=ip,
            open_tcp_ports=open_tcp_ports,
            open_udp_ports=open_udp_ports,
            device_id=device_id,
        )

        return scan_host_id