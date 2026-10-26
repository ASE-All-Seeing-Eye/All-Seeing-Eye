"""ASE-79 (1.2.2.17): Ollama-Anbindung. Ollama wird simuliert, es läuft kein echtes Modell."""
import httpx
import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from all_seeing_eye.analysis import analyzer
from all_seeing_eye.database.models import Analysis, Base, Finding
from all_seeing_eye.settings import settings
from conftest import engine, make_collection, make_rule


def test_anfrage_geht_mit_richtigen_einstellungen_an_ollama(monkeypatch):
    calls = []

    class Client:      # ersetzt ollama.Client, merkt sich den Aufruf und gibt eine feste Antwort
        def __init__(self, **kwargs):
            calls.append(kwargs)

        def chat(self, **kwargs):
            calls.append(kwargs)
            return type("R", (), {"message": type("M", (), {"content": '{"ok": true}'})})

    monkeypatch.setattr(analyzer, "Client", Client)
    answer = analyzer.ask_llm([{"role": "user", "content": "Hallo"}])

    client_args, chat_args = calls
    assert answer == '{"ok": true}'
    assert client_args == {"host": settings.ollama_host, "timeout": settings.ollama_timeout}
    assert chat_args["model"] == settings.ollama_model
    assert chat_args["options"]["temperature"] == 0          # immer gleiche Antwort
    assert chat_args["think"] is False                       # kein langsamer Denkmodus
    assert chat_args["format"] == analyzer.RuleCheck.model_json_schema()


@pytest.fixture
def stored_collection():
    """Speichert Regel und Collection dauerhaft (analyze_collection nutzt eine eigene Verbindung)
    und leert danach alle Tabellen wieder."""
    with Session(engine) as s:
        s.add(make_rule("LLM-1", "llm"))
        collection_id = make_collection(s, outputs={"show running-config": "ip http server"}).id
        s.commit()
    yield collection_id
    with engine.begin() as conn:
        tables = ", ".join(f'"{t.name}"' for t in Base.metadata.sorted_tables)
        conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))


@pytest.mark.parametrize("error", [
    httpx.ReadTimeout("timed out"),                      # Ollama antwortet nicht rechtzeitig
    ConnectionError("Ollama nicht erreichbar"),          # Server aus oder falsche Adresse
])
def test_fehler_bei_ollama_beendet_analyse_als_failed(monkeypatch, stored_collection, error):
    class Client:
        def __init__(self, **kwargs):
            pass

        def chat(self, **kwargs):
            raise error

    monkeypatch.setattr(analyzer, "Client", Client)
    with pytest.raises(type(error)):
        analyzer.analyze_collection(stored_collection)

    with Session(engine) as s:
        analysis = s.scalars(select(Analysis)).one()
        assert analysis.status == "failed"
        assert analysis.error_message == str(error)          # verständliche Meldung gespeichert
        assert analysis.finished_at is not None
        assert s.scalars(select(Finding)).all() == []        # keine halben Ergebnisse
