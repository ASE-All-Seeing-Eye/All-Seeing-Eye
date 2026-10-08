from dataclasses import dataclass, field


@dataclass
class Device:
    device_type: str
    host: str
    username: str | None = None
    password: str | None = None
    secret: str | None = None
    port: int = 22


@dataclass
class RawConfig:
    host: str
    config: str | None = None
    error: str | None = None


@dataclass
class ConfigLine:
    command: str
    position: int
    arguments: list[str] = field(default_factory=list)


@dataclass
class ConfigSection:
    command: str
    start_position: int
    end_position: int
    subcommands: list[ConfigLine] = field(default_factory=list)


@dataclass
class ParsedConfig:
    host: str
    vendor: str
    global_config: list[ConfigLine] = field(default_factory=list)
    config: list[ConfigSection] = field(default_factory=list)


@dataclass
class ScanResult:
    host: str
    is_alive: bool = False
    open_ports: list[int] = field(default_factory=list)
    device_type: str | None = None
    errors: list[str] = field(default_factory=list)

@dataclass
class ConnectionEndpoint:
    device: str
    interface: str

@dataclass
class Connection:
    endpoint_a: ConnectionEndpoint
    endpoint_b: ConnectionEndpoint
