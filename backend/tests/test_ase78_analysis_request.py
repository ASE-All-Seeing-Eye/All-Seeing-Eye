"""ASE-78 (1.2.2.16): Analyseanfragen mit Konfigurationsdaten erstellen."""
import pytest

from all_seeing_eye.analysis import analyzer
from conftest import make_collection, make_rule

CISCO_CONFIG = """Building configuration...
hostname R1
enable secret 9 $9$abcdefghijkl
username admin privilege 15 secret 9 $9$mnopqrstuvwx
username old privilege 1 password 7 0822455D0A16
snmp-server community geheim123 RO
ip http server
line vty 0 4
 transport input ssh
end"""

FORTINET_CONFIG = """#config-version=FGVMK6-7.6.1
config system global
    set hostname "FG"
end
config firewall internet-service-name
    edit "Google-DNS"
    next
end
config system admin
    edit "admin"
        set password ENC SH2xyzGEHEIM
    next
end
config user local
    edit "guest"
        set type password
        set passwd ENC gastGEHEIM
    next
end"""


# ---------------------------------------------------------------------------
# Geheimnisse schwärzen
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("line, expected", [
    ("enable secret 9 $9$abcdefghijkl", "enable secret 9 <entfernt>"),
    ("username admin privilege 15 secret 9 $9$abc", "username admin privilege 15 secret 9 <entfernt>"),
    ("username old password 7 0822455D0A16", "username old password 7 <entfernt>"),
    ("snmp-server community geheim123 RO", "snmp-server community <entfernt> RO"),
    ("        set password ENC SH2xyzGEHEIM", "        set password ENC <entfernt>"),
    ('    set psksecret "mein geheimer key"', "    set psksecret <entfernt>"),
])
def test_redact_entfernt_geheimnisse_aber_behaelt_den_typ(line, expected):
    assert analyzer.redact(line) == expected


def test_redact_laesst_normale_zeilen_unveraendert():
    text = "hostname R1\nip http server\n transport input ssh"
    assert analyzer.redact(text) == text


def test_redact_geht_nicht_ueber_das_zeilenende():
    # "set type password" hat keinen Wert, darf die nächste Zeile nicht verschlucken
    text = "        set type password\n        set passwd ENC gastGEHEIM"
    assert analyzer.redact(text) == "        set type password\n        set passwd ENC <entfernt>"


# ---------------------------------------------------------------------------
# Auswahl und Aufbereitung für das LLM
# ---------------------------------------------------------------------------

def test_fortinet_nur_relevante_bloecke():
    trimmed = analyzer.trim_fortinet_config(FORTINET_CONFIG)
    assert "internet-service-name" not in trimmed
    assert 'edit "admin"' in trimmed and "config user local" in trimmed
    assert "#config-version" in trimmed


def test_llm_bekommt_nur_die_konfiguration_geschwaerzt():
    sections = [("show running-config", CISCO_CONFIG), ("show cdp neighbors", "Device ID R2")]
    chunks = analyzer.prepare_llm_chunks(sections, "cisco")
    assert len(chunks) == 1
    assert "ip http server" in chunks[0]
    assert "Device ID" not in chunks[0]
    for secret in ("$9$abcdefghijkl", "0822455D0A16", "geheim123"):
        assert secret not in chunks[0]


def test_ohne_konfiguration_bekommt_llm_alle_ausgaben():
    chunks = analyzer.prepare_llm_chunks([("show version", "Cisco IOS XE 17.6")], "cisco")
    assert "Cisco IOS XE 17.6" in chunks[0]


def test_fortinet_show_wird_gekuerzt():
    chunks = analyzer.prepare_llm_chunks([("show", FORTINET_CONFIG)], "Fortinet")
    assert "internet-service-name" not in chunks[0]
    assert "SH2xyzGEHEIM" not in chunks[0]


def test_lange_konfiguration_wird_an_zeilengrenzen_geteilt():
    config = "".join(f"interface Gi{i}\n description {'x' * 40}\n" for i in range(1000))
    chunks = analyzer.prepare_llm_chunks([("show running-config", config)], "cisco")
    assert len(chunks) > 1
    assert all(len(c) <= analyzer.MAX_CHARS for c in chunks)
    assert all(c.endswith("\n") for c in chunks)                  # keine Zeile zerschnitten
    assert "".join(chunks).count("interface Gi") == 1000          # nichts verloren


# ---------------------------------------------------------------------------
# Regeln je Hersteller
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rule_vendor, device_vendor, applies", [
    ("all", "cisco", True),
    ("", "Fortinet", True),
    ("cisco", "cisco", True),
    ("Fortinet", "fortinet", True),
    ("fortinet", "FortiGate", True),
    ("cisco", "Fortinet", False),
    ("fortinet", "cisco", False),
])
def test_regel_gilt_nur_fuer_passenden_hersteller(rule_vendor, device_vendor, applies):
    assert analyzer.rule_applies(make_rule("X", vendor=rule_vendor), device_vendor) is applies


# ---------------------------------------------------------------------------
# build_request: Anfrage aus der Datenbank bauen
# ---------------------------------------------------------------------------

def test_build_request_aus_collection(session):
    session.add_all([make_rule("C-REGEX", "regex", vendor="cisco"),
                     make_rule("C-LLM", "llm", vendor="cisco"),
                     make_rule("F-LLM", "llm", vendor="fortinet"),
                     make_rule("ALL-NOT", "not_regex", vendor="all")])
    collection = make_collection(session, outputs={"show running-config": CISCO_CONFIG,
                                                   "show cdp neighbors": "Device ID R2"})

    request = analyzer.build_request(session, collection.id)

    assert request.hostname == "R1" and request.vendor == "cisco"
    assert [r.code for r in request.local_rules] == ["ALL-NOT", "C-REGEX"]
    assert [r.code for r in request.llm_rules] == ["C-LLM"]            # F-LLM gehört zur FortiGate
    assert "Device ID R2" in request.raw_content                       # lokale Regeln sehen alles
    assert "$9$abcdefghijkl" in request.raw_content                    # ungeschwärzt für Regex
    assert "Device ID R2" not in request.chunks[0]                     # LLM nur die Konfiguration
    assert "$9$abcdefghijkl" not in request.chunks[0]                  # geschwärzt


def test_build_request_nimmt_configuration_wenn_keine_commands(session):
    session.add(make_rule("ALL", "llm"))
    collection = make_collection(session, config=CISCO_CONFIG)
    request = analyzer.build_request(session, collection.id)
    assert "ip http server" in request.chunks[0]


def test_nachricht_an_das_llm_enthaelt_nur_eine_regel():
    rule_a, rule_b = make_rule("A", title="Telnet erlaubt"), make_rule("B", title="SNMP public")
    request = analyzer.AnalysisRequest(1, "R1", "cisco", "17.6", [], [rule_a, rule_b], "", ["### show\nx"])
    messages = request.messages("### show\nx", rule_a)
    assert messages[0]["role"] == "system"
    assert "Telnet erlaubt" in messages[1]["content"]
    assert "SNMP public" not in messages[1]["content"]
    assert "R1" in messages[1]["content"] and "17.6" in messages[1]["content"]


@pytest.mark.parametrize("setup, error", [
    (lambda s: None, "existiert nicht"),
    (lambda s: make_collection(s, outputs={"show running-config": CISCO_CONFIG}).id, "Keine SecurityRules"),
    (lambda s: (s.add(make_rule("A")), make_collection(s))[1].id, "keine Ausgaben"),
])
def test_build_request_bricht_mit_klarer_meldung_ab(session, setup, error):
    collection_id = setup(session) or 999
    with pytest.raises(ValueError, match=error):
        analyzer.build_request(session, collection_id)
