from dataclasses import dataclass


@dataclass
class SSHTarget:
    """Verbindungsdaten für Netmiko. Wird zur Laufzeit aus database.models.Device gebaut und nie gespeichert."""
    device_type: str
    host: str
    username: str | None = None
    password: str | None = None
    secret: str | None = None
    port: int = 22


@dataclass
class Credentials:
    username: str
    password: str
    secret: str | None = None


@dataclass
class RawConfig:
    host: str
    config: str | None = None
    error: str | None = None
