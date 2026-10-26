"""Gemeinsame Test-Hilfen. Die Tests laufen ohne Postgres und ohne Ollama:
die Datenbank ist ein SQLite im Speicher, die Postgres-Typen werden dafür umgemappt."""
import os

# Muss vor dem ersten Import von all_seeing_eye passieren, sonst wird die echte DB aus der .env benutzt
os.environ["DATABASE_URL"] = "sqlite://"

import pytest  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB  # noqa: E402
from sqlalchemy.ext.compiler import compiles  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from all_seeing_eye.database.models import (Base, Collection, Command, Configuration,  # noqa: E402
                                            Device, Job, SecurityRule)


@compiles(INET, "sqlite")
def _inet(*_, **__):
    return "VARCHAR"


@compiles(JSONB, "sqlite")
@compiles(ARRAY, "sqlite")
def _json(*_, **__):
    return "JSON"


@pytest.fixture
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s
    engine.dispose()


def make_rule(code, check_type="llm", vendor="all", severity="MEDIUM", check_value="x", title=None):
    return SecurityRule(code=code, title=title or f"Regel {code}", category="Test", severity=severity,
                        vendor=vendor, check_type=check_type, check_value=check_value,
                        recommendation=f"Behebe {code}", source="Test")


def make_collection(session, vendor="cisco", outputs=None, config=None, hostname="R1", ip="10.0.0.1"):
    """Legt Gerät, Job und Collection mit den angegebenen Befehlsausgaben an."""
    device = Device(hostname=hostname, vendor=vendor, management_ip=ip)
    job = Job(target="Test", status="running")
    collection = Collection(device=device, job=job, status="ok")
    for name, output in (outputs or {}).items():
        collection.commands.append(Command(name=name, output=output, parse_status="pending"))
    if config is not None:
        collection.configuration = Configuration(content=config, parse_status="pending")
    session.add(collection)
    session.flush()
    return collection
