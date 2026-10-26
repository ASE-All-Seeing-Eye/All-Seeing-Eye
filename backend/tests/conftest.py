"""Die Tests laufen gegen die lokale PostgreSQL-Datenbank aus TEST_DATABASE_URL (backend/.env).
Jeder Test läuft in einer Transaktion, die danach zurückgerollt wird."""
import os
from pathlib import Path

from dotenv import dotenv_values

TEST_DATABASE_URL = dotenv_values(Path(__file__).parents[1] / ".env")["TEST_DATABASE_URL"]
assert TEST_DATABASE_URL.endswith("_test"), "Nur eine Test-Datenbank verwenden"   # schützt die Team-Datenbank
os.environ["DATABASE_URL"] = TEST_DATABASE_URL

import pytest  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from all_seeing_eye.database.models import (Base, Collection, Command, Configuration,  # noqa: E402
                                            Device, Job, SecurityRule)

engine = create_engine(TEST_DATABASE_URL)
Base.metadata.drop_all(engine)
Base.metadata.create_all(engine)


@pytest.fixture
def session():
    with engine.connect() as conn:
        transaction = conn.begin()
        with Session(bind=conn, join_transaction_mode="create_savepoint") as s:
            yield s
        transaction.rollback()


def make_rule(code, check_type="llm", vendor="all", severity="MEDIUM", check_value="x", title=None):
    return SecurityRule(code=code, title=title or f"Regel {code}", category="Test", severity=severity,
                        vendor=vendor, check_type=check_type, check_value=check_value,
                        recommendation=f"Behebe {code}", source="Test")


def make_collection(session, vendor="cisco", outputs=None, config=None, hostname="R1", ip="10.0.0.1"):
    """Legt Gerät, Job und Collection mit den angegebenen Befehlsausgaben an."""
    device = Device(hostname=hostname, vendor=vendor, management_ip=ip)
    collection = Collection(device=device, job=Job(target="Test", status="running"), status="ok")
    for name, output in (outputs or {}).items():
        collection.commands.append(Command(name=name, output=output, parse_status="pending"))
    if config is not None:
        collection.configuration = Configuration(content=config, parse_status="pending")
    session.add(collection)
    session.flush()
    return collection
