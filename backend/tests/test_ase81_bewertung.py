"""ASE-81 (1.2.2.19): Befunde bewerten, priorisieren und speichern. Ollama wird simuliert."""
import json

from sqlalchemy import select

from all_seeing_eye.analysis import analyzer
from all_seeing_eye.database.models import Analysis, Finding
from all_seeing_eye.settings import settings
from conftest import make_collection, make_rule


def finding(code, severity, detected_by="rule"):
    return analyzer.DetectedFinding(make_rule(code, severity=severity), detected_by, f"Zeile {code}", "Beschreibung")


# ---------------------------------------------------------------------------
# assess: sortieren und bewerten
# ---------------------------------------------------------------------------

def test_sortiert_nach_schwere():
    result = analyzer.assess(1, "R1", [finding("L", "LOW"), finding("C", "CRITICAL"),
                                       finding("M", "medium"), finding("H", "HIGH")])
    assert [f.severity for f in result.findings] == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert result.rating == "CRITICAL"                  # schlechteste Schwere
    assert result.counts == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1}


def test_score_zieht_je_schwere_punkte_ab():
    result = analyzer.assess(1, "R1", [finding("H", "HIGH"), finding("M", "MEDIUM")])
    assert result.score == 100 - 20 - 10


def test_score_wird_nicht_negativ():
    result = analyzer.assess(1, "R1", [finding(f"C{i}", "CRITICAL") for i in range(5)])
    assert result.score == 0


def test_ohne_befunde_ist_das_geraet_ok():
    result = analyzer.assess(1, "R1", [])
    assert result.rating == "OK" and result.score == 100 and result.findings == []


def test_doppelte_regel_nur_einmal_und_regex_hat_vorrang():
    by_llm, by_rule = finding("X", "HIGH", "llm"), finding("X", "HIGH", "rule")
    result = analyzer.assess(1, "R1", [by_llm, by_rule])
    assert result.findings == [by_rule]


# ---------------------------------------------------------------------------
# analyze_collection: kompletter Ablauf mit Speichern in der Datenbank
# ---------------------------------------------------------------------------

CONFIG = "hostname R1\nip http server\nusername admin privilege 15 secret 9 $9$geheim\n"


def test_analyse_speichert_analysis_und_findings(db, monkeypatch):
    db.add_all([
        make_rule("HTTP", "regex", vendor="cisco", severity="MEDIUM", check_value=r"^ip http server"),
        make_rule("SYSLOG", "not_regex", severity="LOW", check_value=r"^logging host"),
        make_rule("ADMIN", "llm", severity="HIGH", title="Standard-Administratorkonto"),
        make_rule("FORTI", "regex", vendor="fortinet", check_value="set admin"),   # gilt nicht für Cisco
    ])
    collection_id = make_collection(db, outputs={"show running-config": CONFIG}).id
    db.commit()
    llm_answer = {"evidence": "username admin privilege 15 secret 9 <entfernt>", "violated": True,
                  "reason": "Das Konto heißt admin."}
    monkeypatch.setattr(analyzer, "ask_llm", lambda messages, schema=None: json.dumps(llm_answer))

    result = analyzer.analyze_collection(collection_id)

    assert result.rating == "HIGH" and result.score == 100 - 20 - 10 - 5
    analysis = db.scalars(select(Analysis)).one()
    assert analysis.status == "done" and analysis.finished_at is not None
    assert analysis.method == "rule+llm" and analysis.ai_model == settings.ollama_model

    rows = {f.rule.code: f for f in db.scalars(select(Finding))}
    assert set(rows) == {"ADMIN", "HTTP", "SYSLOG"}
    admin = rows["ADMIN"]
    assert admin.detected_by == "llm" and admin.severity == "HIGH"
    assert admin.title == "Standard-Administratorkonto" and admin.category == "Test"
    assert admin.description == "Das Konto heißt admin." and admin.recommendation == "Behebe ADMIN"
    assert "$9$geheim" not in admin.evidence                             # Beleg ist geschwärzt
    assert rows["HTTP"].detected_by == "rule" and rows["HTTP"].evidence == "ip http server"
    assert rows["SYSLOG"].evidence is None                               # fehlende Einstellung hat keine Zeile


def test_ohne_befund_wird_das_llm_nicht_gefragt(db, monkeypatch):
    db.add(make_rule("TELNET", "regex", check_value=r"^transport input telnet"))
    collection_id = make_collection(db, outputs={"show running-config": CONFIG}).id
    db.commit()
    monkeypatch.setattr(analyzer, "ask_llm",
                        lambda messages, schema=None: (_ for _ in ()).throw(AssertionError("LLM aufgerufen")))

    analyzer.analyze_collection(collection_id)

    analysis = db.scalars(select(Analysis)).one()
    assert analysis.method == "rule" and analysis.ai_model is None
