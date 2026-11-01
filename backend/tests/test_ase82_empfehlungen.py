"""ASE-82 / H4b: Begründung vom LLM passend zum Gerät, Befehle fest aus commands.py. Ollama wird simuliert."""
import json

import pytest
from sqlalchemy import select

from all_seeing_eye.analysis import analyzer
from all_seeing_eye.analysis.commands import COMMANDS
from all_seeing_eye.analysis.demo import DEMO_RULES
from all_seeing_eye.database.models import Analysis, Finding
from all_seeing_eye.settings import settings
from conftest import make_collection, make_rule

CONFIG = "hostname R1\nip http server\nusername admin privilege 15 secret 9 $9$geheim\n"
ADVICE = json.dumps({"reason": "R1 ist per HTTP erreichbar."})


def stored_collection(db, *rules):
    db.add_all(rules)
    collection_id = make_collection(db, outputs={"show running-config": CONFIG}).id
    db.commit()
    return collection_id


def fake_ollama(monkeypatch, answers):
    """Gibt die Antworten der Reihe nach zurück (eine Exception wird geworfen) und merkt sich jede Anfrage."""
    calls, answers = [], iter(answers)

    def ask(messages, schema=None):
        calls.append(messages[1]["content"])
        answer = next(answers)
        if isinstance(answer, Exception):
            raise answer
        return answer
    monkeypatch.setattr(analyzer, "ask_llm", ask)
    return calls


def findings(db):
    return {f.rule.code: f for f in db.scalars(select(Finding))}


def test_begruendung_vom_llm_landet_im_finding(db, monkeypatch):
    collection_id = stored_collection(db, make_rule("HTTP", "regex", check_value=r"^ip http server"))
    fake_ollama(monkeypatch, [ADVICE])

    analyzer.analyze_collection(collection_id)

    assert findings(db)["HTTP"].reason == "R1 ist per HTTP erreichbar."
    analysis = db.scalars(select(Analysis)).one()
    assert analysis.method == "rule+llm" and analysis.ai_model == settings.ollama_model


def test_befehle_vom_llm_werden_nicht_uebernommen(db, monkeypatch):
    collection_id = stored_collection(db, make_rule("GEN-01", "regex", check_value=r"^username admin"))
    fake_ollama(monkeypatch, [json.dumps({"reason": "Begründung", "recommendation": "set status disable"})])

    analyzer.analyze_collection(collection_id)

    recommendation = findings(db)["GEN-01"].recommendation
    assert "set status disable" not in recommendation
    assert recommendation == f"Behebe GEN-01\n\nBefehle:\n{COMMANDS['GEN-01', 'cisco']}"


def test_regel_ohne_befehle_behaelt_ihren_text(db, monkeypatch):
    collection_id = stored_collection(db, make_rule("HTTP", "regex", check_value=r"^ip http server"))
    fake_ollama(monkeypatch, [ADVICE])

    analyzer.analyze_collection(collection_id)

    assert findings(db)["HTTP"].recommendation == "Behebe HTTP"


@pytest.mark.parametrize("vendor", ["cisco", "fortinet"])
def test_jede_regel_hat_befehle_fuer_ihre_hersteller(vendor):
    missing = [r.code for r in DEMO_RULES if analyzer.rule_applies(r, vendor) and (r.code, vendor) not in COMMANDS]
    assert missing == []


def test_befehle_gehoeren_zu_echten_regeln():
    codes = {r.code for r in DEMO_RULES}
    assert [key for key in COMMANDS if key[0] not in codes] == []


@pytest.mark.parametrize("wrong", [
    "fortiguard-update-interval", "execute fortiguard update", "set status disable", "config system login-banner",
])
def test_vom_llm_erfundene_fortigate_befehle_stehen_nicht_in_der_liste(wrong):
    assert not any(wrong in text for text in COMMANDS.values())


def test_anfrage_enthaelt_geraet_und_beleg_aber_keine_geheimnisse(db, monkeypatch):
    collection_id = stored_collection(db, make_rule("ADMIN", "regex", check_value=r"^username admin"))
    calls = fake_ollama(monkeypatch, [ADVICE])

    analyzer.analyze_collection(collection_id)

    assert "R1" in calls[0] and "cisco" in calls[0]
    assert "username admin privilege 15 secret 9 <entfernt>" in calls[0]
    assert "$9$geheim" not in calls[0]


def test_fehlende_einstellung_zeigt_keinen_regex(db, monkeypatch):
    rule = make_rule("SYSLOG", "not_regex", check_value=r"^logging host", title="Syslog-Server eingetragen")
    collection_id = stored_collection(db, rule)
    calls = fake_ollama(monkeypatch, [ADVICE])

    analyzer.analyze_collection(collection_id)

    assert "die Einstellung fehlt" in calls[0] and "^logging host" not in calls[0]
    assert findings(db)["SYSLOG"].description == "Erwartete Einstellung fehlt: Syslog-Server eingetragen"


def test_ungueltige_antwort_betrifft_nur_dieses_finding(db, monkeypatch):
    collection_id = stored_collection(db, make_rule("ADMIN", "regex", check_value=r"^username admin"),
                                      make_rule("HTTP", "regex", check_value=r"^ip http server"))
    fake_ollama(monkeypatch, ['{"reason": ""}', ADVICE])

    analyzer.analyze_collection(collection_id)

    rows = findings(db)
    assert rows["ADMIN"].reason == "Verstoß gegen Regel ADMIN (Test)."      # Text aus der Regel
    assert rows["HTTP"].reason == "R1 ist per HTTP erreichbar."


def test_ollama_aus_analyse_laeuft_mit_regeltexten_durch(db, monkeypatch):
    collection_id = stored_collection(db, make_rule("ADMIN", "regex", check_value=r"^username admin"),
                                      make_rule("GEN-01", "regex", check_value=r"^ip http server"))
    calls = fake_ollama(monkeypatch, [ConnectionError("Ollama nicht erreichbar")])

    result = analyzer.analyze_collection(collection_id)

    assert len(calls) == 1                                                 # nicht bei jedem Finding nochmal warten
    assert len(result.findings) == 2 and findings(db)["ADMIN"].recommendation == "Behebe ADMIN"
    assert "Befehle:" in findings(db)["GEN-01"].recommendation             # feste Befehle auch ohne LLM
    analysis = db.scalars(select(Analysis)).one()
    assert analysis.status == "done" and analysis.method == "rule" and analysis.ai_model is None
