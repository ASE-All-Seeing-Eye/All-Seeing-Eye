from pathlib import Path
from ttp import ttp
import shlex

from all_seeing_eye.parser.models import ParsedDevice, ParsedInterface, ParsedNeighbor
from all_seeing_eye.parser.base import Parser
from all_seeing_eye.parser.normalize import normalize_hostname, to_prefix

TEMPLATES = Path(__file__).parent / "templates"
REQUIRED_DEVICE_FIELDS = {
    "hostname": "get system status",
    "os_version": "get system status",
    "model": "get hardware status"
}

def load_template(name: str) -> str:
    return (TEMPLATES / name).read_text(encoding="utf-8") 

SYSTEM_STATUS_TEMPLATE = load_template("fortinet_system_status.ttp")
HARDWARE_STATUS_TEMPLATE = load_template("fortinet_hardware_status.ttp")
INTERFACES_TEMPLATE = load_template("fortinet_interfaces.ttp")
LLDP_NEIGHBORS_TEMPLATE = load_template("fortinet_lldp_neighbors.ttp")
INTERFACE_PHYSICAL_TEMPLATE = load_template("fortinet_interface_physical.ttp")

TEMPLATES_BY_COMMAND = {
    "get system status": SYSTEM_STATUS_TEMPLATE,
    "get hardware status": HARDWARE_STATUS_TEMPLATE,
    "show system interface": INTERFACES_TEMPLATE,
    "diagnose lldprx neighbor details": LLDP_NEIGHBORS_TEMPLATE,
    "get system interface physical": INTERFACE_PHYSICAL_TEMPLATE
}

class FortiParser(Parser):
    def __init__(self):
        self.os_type = "fortios"

    def _parse(self, commands: dict[str, str], command: str, errors: list[str]) -> dict | None:
        output = commands.get(command)
        if not output:
            errors.append(f"{command}: keine Ausgabe vorhanden")
            return None
        parsed = self.parse_command(command, output)
        if parsed is None:
            errors.append(f"{command}: Ausgabe nicht erkannt")
        return parsed

    def parse_device(self, commands: dict[str, str]) -> tuple[ParsedDevice, list[str]]:
        errors: list[str] = []
        device = ParsedDevice(vendor="fortinet", os_type=self.os_type)
        status = self._parse(commands, "get system status", errors)
        if status:
            device.hostname = normalize_hostname(status.get("hostname"))
            version_line = status.get("version_line") or ""
            device.os_version = version_line.partition(" v")[2].split(",")[0] or None
        hardware = self._parse(commands, "get hardware status", errors)
        if hardware:
            device.model = hardware.get("model")

        for field, command in REQUIRED_DEVICE_FIELDS.items():
            if getattr(device, field) is None:
                errors.append(f"{command}: {field} fehlt")
        return device, errors

    # TODO: MAC-Addresse abfragen
    def parse_interfaces(self, commands: dict[str, str]) -> tuple[list[ParsedInterface], list[str]]:
        errors: list[str] = []
        parsed = self._parse(commands, "show system interface", errors)
        interfaces: list[ParsedInterface] = []
        for entry in (parsed or {}).get("interfaces") or []:
            if not isinstance(entry, dict) or not entry.get("name"):
                errors.append(f"Interface-Eintrag ohne Namen übersprungen: {entry!r}")
                continue
            ip, mask = entry.get("ip_address"), entry.get("mask")
            if ip == "0.0.0.0":
                ip = None
            interfaces.append(ParsedInterface(
                name=entry["name"],
                description=entry.get("description"),
                ip_address=to_prefix(ip, mask) if ip and mask else None,
                status="administratively down" if entry.get("status") == "down" else None,
                mode="routed" if ip else None,
                vlan=entry.get("vlan")
            ))
        parsed = self._parse(commands, "get system interface physical", errors)
        for entry in (parsed or {}).get("interfaces") or []:
            if not isinstance(entry, dict) or not entry.get("name"):
                errors.append(f"Interface-Eintrag ohne Namen übersprungen: {entry!r}")
                continue
            for interface in interfaces:
                if interface.name == entry["name"] and interface.status is None:
                    interface.status = entry.get("status")
        return interfaces, errors

    def parse_neighbors(self, commands: dict[str, str]) -> tuple[list[ParsedNeighbor], list[str]]:
        errors: list[str] = []
        parsed = self._parse(commands, "diagnose lldprx neighbor details", errors)
        neighbors: list[ParsedNeighbor] = []
        for entry in (parsed or {}).get("neighbors") or []:
            if not isinstance(entry, dict):
                errors.append(f"Unerwarteter Nachbar Eintrag: {entry!r}")
                continue
            if not entry.get("local_interface"):
                errors.append("LLDP-Eintrag ohne lokales Interface übersprungen")
                continue
            remote_interface = entry.get("remote_interface")
            remote_ip = entry.get("remote_ip")
            neighbors.append(ParsedNeighbor(
                local_interface=entry.get("local_interface"),
                method="lldp",
                remote_hostname=normalize_hostname(entry.get("remote_hostname")),
                remote_interface=remote_interface if remote_interface else None,
                remote_ip=remote_ip if remote_ip else None
            ))
        return neighbors, errors

    def parse_config(self, commands: dict[str, str]) -> tuple[dict, list[str]]:
        errors: list[str] = []
        config = commands.get("show full-configuration")
        if not config:
            errors.append("show full-configuration: keine Ausgabe vorhanden")
            return {}, errors

        root: dict = {}
        stack: list[dict] = [root]
        for line in config.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                parts = shlex.split(line)
            except ValueError:
                continue

            keyword, args = parts[0], parts[1:]
            current = stack[-1]
            if keyword == "config":
                stack.append(current.setdefault(" ".join(args), {}))
            elif keyword == "edit":
                stack.append(current.setdefault(args[0] if args else "", {}))
            elif keyword in ("next", "end"):
                if len(stack) > 1:
                    stack.pop()
            elif keyword == "set" and args:
                values = args[1:]
                current[args[0]] = values[0] if len(values) == 1 else values
            elif keyword == "unset" and args:
                current[args[0]] = None
        return root, errors

    def parse_command(self, command: str, output: str) -> dict | None:
        template = TEMPLATES_BY_COMMAND.get(command)
        if template is None:
            return None
        parser = ttp(data=output, template=template)
        parser.parse()
        return parser.result()[0][0] or None
