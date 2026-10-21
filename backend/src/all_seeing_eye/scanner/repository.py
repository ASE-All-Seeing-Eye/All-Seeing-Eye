from datetime import datetime, timezone
from ipaddress import IPv4Address

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from all_seeing_eye.database.models import Device


class ResultRepository:
    def __init__(self, session: Session):
        self.session = session

    def save_device(self, device) -> Device:
        ip = str(IPv4Address(str(device.management_ip)))

        values = {"management_ip": ip}

        for field in ("hostname", "vendor", "model", "os_version"):
            value = getattr(device, field, None)

            if isinstance(value, str):
                value = value.strip() or None

            values[field] = value

        statement = insert(Device).values(**values)

        statement = statement.on_conflict_do_update(
            index_elements=[Device.management_ip],
            set_={
                field: func.coalesce(
                    getattr(statement.excluded, field),
                    getattr(Device, field),
                )
                for field in (
                    "hostname",
                    "vendor",
                    "model",
                    "os_version",
                )
            },
        ).returning(Device)

        saved_device = self.session.scalars(
            statement,
            execution_options={"populate_existing": True},
        ).one()

        return saved_device

