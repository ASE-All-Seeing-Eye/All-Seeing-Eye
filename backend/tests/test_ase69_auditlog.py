"""ASE-69 / H1a: Anmeldeversuche des Collectors landen in der Tabelle auditlog."""
from sqlalchemy import select

from all_seeing_eye.collector.collector import CollectionResult
from all_seeing_eye.collector.models import RawConfig
from all_seeing_eye.collector.repository import CollectionRepository
from all_seeing_eye.database.models import AuditLog, Device


def save(session, result):
    device = Device(hostname="R1", vendor="cisco", management_ip="10.0.0.1")
    session.add(device)
    repo = CollectionRepository(session)
    repo.save_result(repo.create_job("Test"), device, result)
    session.flush()
    return device, session.scalars(select(AuditLog)).one()


def test_falsches_passwort_wird_protokolliert(session):
    device, log = save(session, CollectionResult(host="10.0.0.1", error="Authentifizierung fehlgeschlagen"))
    assert (log.actor, log.action, log.result) == ("collector", "device_login", "failed")
    assert (log.object_type, log.object_id) == ("device", device.id)
    assert log.message == "10.0.0.1: Authentifizierung fehlgeschlagen"


def test_erfolgreiche_anmeldung_wird_protokolliert(session):
    result = CollectionResult(host="10.0.0.1", outputs={"show version": RawConfig(host="10.0.0.1", config="IOS")})
    _, log = save(session, result)
    assert log.result == "ok" and log.message == "10.0.0.1: Anmeldung erfolgreich"
