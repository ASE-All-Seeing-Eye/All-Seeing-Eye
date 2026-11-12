from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from all_seeing_eye.constants import Action, Actor, Status
from all_seeing_eye.database.models import AuditLog, Collection, Command, Configuration, Device, Job

from .collector import CollectionResult
from .models import Credentials, SSHTarget

DEVICE_TYPES = {"cisco": "cisco_ios", "nxos": "cisco_nxos", "fortinet": "fortinet"}

CONFIG_COMMANDS = {"cisco": "show running-config", "fortinet": "show full-configuration"}


def vendor_key(vendor: str | None) -> str:
    return "fortinet" if "forti" in (vendor or "").lower() else "cisco"


def to_target(device: Device, credentials: Credentials) -> SSHTarget:
    platform = "nxos" if (device.os_type or "").lower() == "nxos" else vendor_key(device.vendor)
    return SSHTarget(
        device_type=DEVICE_TYPES[platform],
        host=str(device.management_ip),
        username=credentials.username,
        password=credentials.password,
        secret=credentials.secret,
    )


def collection_status(result: CollectionResult) -> str:
    if result.error:
        return "failed"
    return "ok" if result.success else "partial"


class CollectionRepository:
    def __init__(self, session: Session):
        self.session = session

    def devices(self) -> list[Device]:
        return list(self.session.scalars(select(Device)))

    def create_job(self, target: str) -> Job:
        job = Job(target=target, status="running")
        self.session.add(job)
        self.session.flush()
        return job

    def save_result(self, job: Job, device: Device, result: CollectionResult) -> Collection:
        if result.hostname:
            device.hostname = result.hostname

        collection = Collection(device=device, job=job, status=collection_status(result),
                                error_message=result.error)
        self.session.add(collection)

        for name, raw in result.outputs.items():
            collection.commands.append(Command(
                name=name,
                output=raw.config,
                parse_status="error" if raw.error else "pending",
                error_message=raw.error,
            ))

        config = result.outputs.get(CONFIG_COMMANDS[vendor_key(device.vendor)])
        if config and config.config:
            collection.configuration = Configuration(content=config.config, parse_status="pending")

        self.session.flush()
        self.session.add(AuditLog(actor=Actor.COLLECTOR, action=Action.DEVICE_LOGIN, object_type="device",
                                  object_id=device.id, result=Status.FAILED if result.error else Status.OK,
                                  message=f"{device.management_ip}: {result.error or 'Anmeldung erfolgreich'}"))
        return collection

    def finish_job(self, job: Job, collections: list[Collection]) -> None:
        failed = [c for c in collections if c.status == "failed"]
        job.status = "failed" if collections and len(failed) == len(collections) else "done"
        job.finished_at = datetime.now(timezone.utc)
        if failed:
            job.error_message = f"{len(failed)} von {len(collections)} Geräten nicht erreichbar"
