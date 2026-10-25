from dataclasses import dataclass, field

@dataclass
class ParsedDevice:
    hostname: str | None = None
    vendor: str | None = None
    model: str | None = None
    os_type: str | None = None
    os_version: str | None = None

@dataclass
class ParsedInterface:
    name: str
    description: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    status: str | None = None
    mode: str | None = None
    vlan: int | None = None

@dataclass
class ParsedNeighbor:
    local_interface: str
    method: str
    remote_hostname: str | None = None
    remote_interface: str | None = None
    remote_ip: str | None = None

@dataclass
class ParsedResult:
    device: ParsedDevice = field(default_factory=ParsedDevice)
    interfaces: list[ParsedInterface] = field(default_factory=list)
    neighbors: list[ParsedNeighbor] = field(default_factory=list)
    config: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)