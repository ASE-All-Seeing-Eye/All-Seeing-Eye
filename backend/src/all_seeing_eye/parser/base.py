from abc import ABC, abstractmethod
from all_seeing_eye.parser.models import ParsedDevice, ParsedInterface, ParsedNeighbor, ParsedResult

class Parser(ABC):
    def parse(self, commands: dict[str, str]) -> ParsedResult:
        result = ParsedResult()

        result.device, errors = self.parse_device(commands)
        result.errors += errors

        result.interfaces, errors = self.parse_interfaces(commands)
        result.errors += errors

        result.neighbors, errors = self.parse_neighbors(commands)
        result.errors += errors

        result.config, errors = self.parse_config(commands)
        result.errors += errors

        return result

    @abstractmethod
    def parse_device(self, commands: dict[str, str]) -> tuple[ParsedDevice, list[str]]:
        pass

    @abstractmethod
    def parse_interfaces(self, commands: dict[str, str]) -> tuple[list[ParsedInterface], list[str]]:
        pass

    @abstractmethod
    def parse_neighbors(self, commands: dict[str, str]) -> tuple[list[ParsedNeighbor], list[str]]:
        pass

    @abstractmethod
    def parse_config(self, commands: dict[str, str]) -> tuple[dict, list[str]]:
        pass

    @abstractmethod
    def parse_command(self, command: str, output: str) -> dict | None:
        pass