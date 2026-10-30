"""ASE-79 (1.2.2.17): Ollama-Anbindung. Ollama wird simuliert, es läuft kein echtes Modell."""
import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from all_seeing_eye.analysis import analyzer
from all_seeing_eye.database.models import Analysis, Finding
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
    # kein langer Denkmodus, gpt-oss lässt sich nur auf "low" stellen
    assert chat_args["think"] == ("low" if "gpt-oss" in settings.ollama_model else False)
    assert chat_args["format"] == analyzer.RuleCheck.model_json_schema()


@pytest.fixture
def stored_collection(db):
    db.add(make_rule("LLM-1", "llm"))
    collection_id = make_collection(db, outputs={"show running-config": "ip http server"}).id
    db.commit()
    return collection_id


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
