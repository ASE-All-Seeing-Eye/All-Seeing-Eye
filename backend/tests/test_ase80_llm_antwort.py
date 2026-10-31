"""ASE-80 (1.2.2.18): LLM-Ausgaben verarbeiten und auf Struktur prüfen. Ollama wird simuliert."""
import json

import pytest
from pydantic import ValidationError

from all_seeing_eye.analysis import analyzer
from conftest import make_rule

CONFIG = """### show running-config
hostname R1

no ip http server
ip http secure-server
username admin privilege 15 secret 9 <entfernt>
"""
RULE = make_rule("ADMIN", title="Standard-Administratorkonto")


def answer(evidence="", violated=False, reason="Begründung"):
    return json.dumps({"evidence": evidence, "violated": violated, "reason": reason})


# ---------------------------------------------------------------------------
# parse_check: eine Antwort prüfen
# ---------------------------------------------------------------------------

def test_verstoss_mit_echter_zeile_wird_zum_finding():
    finding = analyzer.parse_check(
        answer("username admin privilege 15 secret 9 <entfernt>", True, "Konto heißt admin."), RULE, CONFIG)
    assert finding.rule is RULE
    assert finding.detected_by == "llm"
    assert finding.evidence == "username admin privilege 15 secret 9 <entfernt>"
    assert finding.description == "Konto heißt admin."


def test_kein_verstoss_kein_finding():
    assert analyzer.parse_check(answer("hostname R1", False), RULE, CONFIG) is None


@pytest.mark.parametrize("evidence", [
    "set admin enable",       # erfunden, steht nicht in der Config
    "ip http server",         # nur ein Teil von "no ip http server", bedeutet das Gegenteil
    "",                       # kein Beleg (die Config enthält eine Leerzeile, die darf nicht zählen)
])
def test_verstoss_ohne_echten_beleg_wird_verworfen(evidence):
    assert analyzer.parse_check(answer(evidence, True), RULE, CONFIG) is None


def test_fehlende_begruendung_ist_erlaubt():
    assert analyzer.parse_check('{"evidence": "", "violated": false}', RULE, CONFIG) is None
    finding = analyzer.parse_check('{"evidence": "username admin privilege 15 secret 9 <entfernt>", "violated": true}',
                                   RULE, CONFIG)
    assert finding.description == RULE.title                          # Regeltitel als Ersatz


FORTI_CONFIG = 'config system snmp community\n    edit 1\n        set name "public"\n    next\nend\n'


def test_beleg_ueber_mehrere_echte_zeilen_zaehlt():
    evidence = 'config system snmp community\n    edit 1\n        set name "public"'
    assert analyzer.parse_check(answer(evidence, True), RULE, FORTI_CONFIG) is not None


def test_beleg_mit_einer_erfundenen_zeile_wird_verworfen():
    evidence = 'config system snmp community\n    set name "erfunden"'
    assert analyzer.parse_check(answer(evidence, True), RULE, FORTI_CONFIG) is None


def test_gross_kleinschreibung_und_leerzeichen_sind_egal():
    evidence = "  USERNAME admin   privilege 15 secret 9 <entfernt> "
    assert analyzer.parse_check(answer(evidence, True), RULE, CONFIG) is not None


@pytest.mark.parametrize("text", [
    "Die Regel ist verletzt.",                                         # gar kein JSON
    '{"evidence": "hostname R1"}',                                     # Felder fehlen
    '{"evidence": "x", "violated": "vielleicht", "reason": "r"}',      # violated kein true/false
])
def test_ungueltige_antwort_ist_ein_fehler(text):
    with pytest.raises(ValidationError):
        analyzer.parse_check(text, RULE, CONFIG)


# ---------------------------------------------------------------------------
# run_llm: Ablauf über alle Regeln
# ---------------------------------------------------------------------------

def request(rules, chunks=(CONFIG,)):
    return analyzer.AnalysisRequest(1, "R1", "cisco", "", [], list(rules), "", list(chunks))


def fake_ollama(monkeypatch, answers):
    """Ersetzt ask_llm: gibt die Antworten der Reihe nach zurück und merkt sich jede Anfrage."""
    calls, answers = [], iter(answers)
    monkeypatch.setattr(analyzer, "ask_llm", lambda messages: calls.append(messages[1]["content"]) or next(answers))
    return calls


def test_nach_ungueltiger_antwort_gibt_es_einen_zweiten_versuch(monkeypatch):
    calls = fake_ollama(monkeypatch, ["kein JSON", answer("username admin privilege 15 secret 9 <entfernt>", True)])
    findings = analyzer.run_llm(request([RULE]))
    assert len(calls) == 2 and len(findings) == 1


def test_zwei_ungueltige_antworten_brechen_ab(monkeypatch):
    fake_ollama(monkeypatch, ["kein JSON", "wieder kein JSON"])
    with pytest.raises(RuntimeError, match="keine gültige LLM-Antwort"):
        analyzer.run_llm(request([RULE]))


def test_eine_anfrage_pro_regel(monkeypatch):
    rules = [make_rule("A", title="Telnet erlaubt"), make_rule("B", title="SNMP public")]
    calls = fake_ollama(monkeypatch, [answer(), answer()])
    analyzer.run_llm(request(rules))
    assert len(calls) == 2
    assert "Telnet erlaubt" in calls[0] and "SNMP public" not in calls[0]
    assert "SNMP public" in calls[1] and "Telnet erlaubt" not in calls[1]


def test_nach_einem_treffer_werden_weitere_teile_uebersprungen(monkeypatch):
    calls = fake_ollama(monkeypatch, [answer("username admin privilege 15 secret 9 <entfernt>", True)])
    findings = analyzer.run_llm(request([RULE], chunks=[CONFIG, "### show running-config (Fortsetzung)\nend\n"]))
    assert len(calls) == 1 and len(findings) == 1
