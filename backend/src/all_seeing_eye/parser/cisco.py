from genie.conf.base import Device
from genie.metaparser.util.exceptions import SchemaEmptyParserError
from genie.utils.config import Config

from all_seeing_eye.parser.base import Parser

GENIE_OS = {"ios": "ios", "ios_xe": "iosxe", "nx_os": "nxos"}

class CiscoParser(Parser):
    def __init__(self, os_type: str):
        self.os_type = os_type
        self.device = Device("parser", os=GENIE_OS[os_type])
        self.device.custom.setdefault("abstraction", {})["order"] = ["os"]

    def parse(self, commands: dict[str, str], command: str, errors: list[str]) -> dict | None:
        output = commands.get(command)
        if not output:
            errors.append(f"{command}: keine Ausgabe vorhanden")
            return None
        parsed = self.parse_command(command, output)
        if parsed is None:
            errors.append(f"{command}: Ausgabe nicht erkannt")
        return parsed

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