from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from all_seeing_eye.database.models import Configuration, Device

from .collector import CollectionResult
from .models import Credentials, SSHTarget

DEVICE_TYPES = {"cisco": "cisco_ios", "fortinet": "fortinet"}


def vendor_key(vendor: str) -> str:
    """Bringt den Hersteller aus der DB auf 'cisco' oder 'fortinet'."""
    return "fortinet" if "forti" in (vendor or "").lower() else "cisco"


def to_target(device: Device, credentials: Credentials) -> SSHTarget:
    return SSHTarget(
        device_type=DEVICE_TYPES[vendor_key(device.vendor)],
        host=str(device.management_ip),
        username=credentials.username,
        password=credentials.password,
        secret=credentials.secret,
    )


def build_content(result: CollectionResult) -> str:
    """Alle erfolgreichen Befehlsausgaben in einen Text, jeweils mit Überschrift."""
    return "\n".join(f"### {cmd}\n{raw.config.strip()}\n"
                     for cmd, raw in result.outputs.items() if raw.config)


class CollectionRepository:
    def __init__(self, session: Session):
        self.session = session

    def devices(self) -> list[Device]:
        return list(self.session.scalars(select(Device)))

    def save_result(self, device: Device, result: CollectionResult) -> Configuration | None:
        content = build_content(result)
        if not content:
            return None
        if result.hostname:
            device.hostname = result.hostname
        # PK ist device_id -> pro Gerät genau eine Configuration, wird überschrieben
        config = self.session.get(Configuration, device.id)
        if config is None:
            config = Configuration(device_id=device.id)
            self.session.add(config)
        config.content = content
        config.collected_at = datetime.now(timezone.utc)
        return config
