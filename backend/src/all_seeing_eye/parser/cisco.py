from genie.conf.base import Device
from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.utils.config import Config

from all_seeing_eye.parser.base import Parser
from all_seeing_eye.parser.models import ParsedDevice, ParsedInterface, ParsedNeighbor

GENIE_OS = {"ios": "ios", "ios_xe": "iosxe", "nx_os": "nxos"}
REQUIRED_DEVICE_FIELDS = {"hostname", "model", "os_version"}

class CiscoParser(Parser):
    def __init__(self, os_type: str):
        self.os_type = os_type
        self.device = Device("parser", os=GENIE_OS[os_type])
        self.device.custom.setdefault("abstraction", {})["order"] = ["os"]

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
        device = ParsedDevice(vendor="cisco", os_type=self.os_type)
        parsed = self.parse(commands, "show version", errors)
        if parsed and self.os_type == "nx_os":
            hardware = parsed.get("platform", {}).get("hardware", {})
            device.hostname = hardware.get("device_name")
            device.model = hardware.get("model")
            device.os_version = parsed.get("platform", {}).get("software", {}).get("system_version")
        elif parsed:
            version = parsed.get("version", {})
            device.hostname = version.get("hostname")
            device.model = version.get("chassis") or version.get("platform")
            device.os_version = version.get("version")

        for field in REQUIRED_DEVICE_FIELDS:
            if getattr(device, field) is None:
                errors.append(f"show version: {field} fehlt")
        return device, errors

    def parse_interfaces(self, commands: dict[str, str]) -> tuple[list[ParsedInterface], list[str]]:
        errors: list[str] = []
        parsed = self.parse(commands, "show interfaces", errors)
        interfaces: dict[str, ParsedInterface] = {}
        for name, data in (parsed or {}).items():
            interfaces.append(ParsedInterface(
                name=name,
                description=data.get("description"),
                ip_address=next(iter(data.get("ipv4", {})), None),
                mac_address=data.get("mac_address"),
                status=data.get("oper_status"),
            ))
        output = commands.get("show interfaces switchport")
        switchport = self.parse_command("show interfaces switchport", output) if output else None
        for name, data in (switchport or {}).items():
            interface = interfaces.get(name)
            if interface is None or not data.get("switchport_enable"):
                continue
            interface.mode = data.get("operational_mode")
            if interface.mode == "access" and data.get("access_vlan"):
                interface.vlan = int(data["access_vlan"])

        for interface in interfaces.values():
            if interface.mode is None and interface.ip_address:
                interface.mode = "routed"
        return list(interfaces.values()), errors

    def parse_neighbors(self, commands: dict[str, str]) -> tuple[list[ParsedNeighbor], list[str]]: 
        errors: list[str] = []
        neighbors: list[ParsedNeighbor] = []
        output = commands.get("show cdp neighbors detail")
        parsed = self.parse_command("show cdp neighbors detail", output) if output else None
        for entry in (parsed or {}).get("index", {}).values():
            if not entry.get("local_interface"):
                errors.append("CDP-Eintrag ohne lokales Interface übersprungen")
                continue
            addresses = entry.get("management_addresses") or entry.get("entry_addresses") or {}
            neighbors.append(ParsedNeighbor(
                local_interface=entry["local_interface"],
                method="cdp",
                remote_hostname=(entry.get("device_id") or "").split(".")[0] or None,
                remote_interface=(entry["port_id"]) if entry.get("port_id") else None,
                remote_ip=next(iter(addresses), None)
            ))
        output = commands.get("show lldp neighbors detail")
        parsed = self.parse_command("show lldp neighbors detail", output) if output else None
        for local_name, local in (parsed or {}).get("interfaces", {}).items():
            for remote_port, port in local.get("port_id", {}).items():
                for remote_name, neighbor in port.get("neighbors", {}).items():
                    neighbors.append(ParsedNeighbor(
                        local_interface=local_name,
                        method="lldp",
                        remote_hostname=(neighbor.get("system_name") or remote_name.split(".")[0]),
                        remote_interface=remote_port,
                        remote_ip=neighbor.get("management_address")
                    ))
        if commands.get("show cdp neighbors detail") is None or commands.get("show lldp neighbors detail") is None:
            errors.append("Keine CDP oder LLDP Ausgabe vorhanden")
        return neighbors, errors

    def parse_command(self, command: str, output: str) -> dict | None:
        try:
            return self.device.parse(command, output=output)
        except SchemaEmptyParserError:
            return None
        except Exception:
            return None

    def parse_config(self, commands: dict[str, str]) -> tuple[dict, list[str]]:
        text = commands.get("show running-config")
        if not text:
            return {}, ["show running-config: keine Ausgabe vorhanden"]
        config = Config(text)
        config.tree()
        return config.config, []