"""Kurze Demo: analysiert die .txt-Ausgaben des Collectors mit Ollama, ganz ohne Datenbank.

Start (im Ordner backend):
    uv run python -m all_seeing_eye.analysis.demo src/all_seeing_eye/collector/gns3_output/R1
    uv run python -m all_seeing_eye.analysis.demo src/all_seeing_eye/collector/gns3_output/R1 src/all_seeing_eye/collector/gns3_output/R2
    uv run python -m all_seeing_eye.analysis.demo src/all_seeing_eye/collector/gns3_output     # alle Geräte

Die Regeln unten sind nur Beispiele für die Demo, die echten kommen später aus der Tabelle securityrule.
"""
import os

# Der Analyzer importiert die DB-Einstellungen, für die Demo wird keine Datenbank gebraucht
os.environ.setdefault("DATABASE_URL", "sqlite://")

import argparse  # noqa: E402
import logging  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

from all_seeing_eye.analysis import analyzer  # noqa: E402
from all_seeing_eye.database.models import SecurityRule  # noqa: E402
from all_seeing_eye.settings import settings  # noqa: E402


def demo_rule(code, title, category, severity, vendor, check_type, check_value, recommendation):
    return SecurityRule(code=code, title=title, category=category, severity=severity, vendor=vendor,
                        check_type=check_type, check_value=check_value, recommendation=recommendation,
                        source="Demo")


DEMO_RULES = [
    # ---- werden von Ollama geprüft ----
    demo_rule("LLM-01", "Unverschlüsselte Verwaltung (Telnet/HTTP)", "Management", "HIGH", "all", "llm",
              "Telnet oder HTTP ohne s ist als Verwaltungszugang erlaubt (z. B. 'transport input telnet', "
              "'ip http server', 'set allowaccess ... http' oder '... telnet', 'set admin-telnet enable'). "
              "Reine Portnummern wie 'set admin-port 80' oder 'admin-telnet-port 23' sind kein Verstoß",
              "Nur SSH und HTTPS für die Verwaltung erlauben"),
    demo_rule("LLM-02", "SNMP mit Standard-Community", "Management", "CRITICAL", "all", "llm",
              "SNMP-Community heißt 'public' oder 'private'",
              "Eigene Community bzw. SNMPv3 verwenden"),

    # ---- werden direkt in Python geprüft: alle Hersteller ----
    demo_rule("GEN-01", "Standard-Administratorkonto 'admin'", "Authentifizierung", "MEDIUM", "all", "regex",
              r'^username admin\b|(?<=config system admin\n)\s*edit "admin"',
              "Personalisierte Admin-Konten anlegen und 'admin' deaktivieren"),
    demo_rule("GEN-02", "Kein externer Syslog-Server", "Logging", "MEDIUM", "all", "not_regex",
              r"^logging host|config log syslogd setting\s*\n(\s+set .*\n)*?\s+set status enable",
              "Logs an einen zentralen Syslog-Server senden"),
    demo_rule("GEN-03", "Kein Login-Banner", "Management", "LOW", "all", "not_regex",
              r"^banner (login|motd)|set pre-login-banner enable",
              "Login-Banner mit rechtlichem Hinweis konfigurieren"),

    # ---- Cisco IOS ----
    demo_rule("CIS-01", "Passwörter im Klartext oder mit Typ 7", "Authentifizierung", "HIGH", "cisco", "regex",
              r"^enable password|^username \S+ .*password (0|7) ",
              "'enable secret' bzw. 'username ... secret' (Typ 8/9) verwenden"),
    demo_rule("CIS-02", "Keine Passwort-Verschlüsselung (service password-encryption)", "Authentifizierung",
              "LOW", "cisco", "not_regex", r"^service password-encryption",
              "'service password-encryption' aktivieren"),
    demo_rule("CIS-03", "Kein AAA (zentrale Authentifizierung)", "Authentifizierung", "MEDIUM", "cisco",
              "regex", r"^no aaa new-model",
              "AAA aktivieren und Anmeldung über RADIUS/TACACS+ führen"),
    demo_rule("CIS-04", "Kein Schutz gegen Brute-Force-Anmeldungen", "Authentifizierung", "MEDIUM", "cisco",
              "not_regex", r"^login block-for",
              "'login block-for ... attempts ... within ...' konfigurieren"),
    demo_rule("CIS-05", "VTY-Zugriff nicht per ACL eingeschränkt", "Management", "MEDIUM", "cisco",
              "not_regex", r"^\s*access-class \S+ in",
              "Auf den VTY-Leitungen eine 'access-class' mit erlaubten Management-IPs setzen"),
    demo_rule("CIS-06", "Kein NTP-Server", "Logging", "LOW", "cisco", "not_regex", r"^ntp server",
              "NTP-Server konfigurieren, damit Logs korrekte Zeitstempel haben"),
    demo_rule("CIS-07", "SSH Version 1 erlaubt", "Protokolle", "HIGH", "cisco", "not_regex", r"^ip ssh version 2",
              "'ip ssh version 2' setzen"),
    demo_rule("CIS-08", "Kein Session-Timeout", "Management", "MEDIUM", "cisco", "regex", r"exec-timeout 0( 0)?$",
              "'exec-timeout 10 0' oder kürzer setzen"),
    demo_rule("CIS-09", "CDP aktiv (verrät Geräteinformationen)", "Protokolle", "LOW", "cisco", "regex",
              r"^Device ID|Total cdp entries displayed",
              "CDP auf Interfaces zu nicht vertrauenswürdigen Netzen deaktivieren"),

    # ---- FortiGate ----
    demo_rule("FGT-01", "Admin-Zugriff nicht auf vertrauenswürdige Hosts beschränkt", "Management", "MEDIUM",
              "fortinet", "not_regex", r"set trusthost\d+ (?!0\.0\.0\.0 0\.0\.0\.0)",   # 0.0.0.0 = Standard, alles erlaubt
              "Beim Admin-Konto 'set trusthost1 <Management-Netz>' setzen"),
    demo_rule("FGT-02", "Keine Passwort-Richtlinie für Admins", "Authentifizierung", "MEDIUM", "fortinet",
              "not_regex", r"config system password-policy\s*\n(\s+set .*\n)*?\s+set status enable",
              "'config system password-policy' mit Mindestlänge und Komplexität aktivieren"),
    demo_rule("FGT-03", "Lokales Gastkonto vorhanden", "Authentifizierung", "LOW", "fortinet", "regex",
              r'^\s*edit "guest"$', "Nicht benötigte lokale Konten entfernen"),
    demo_rule("FGT-04", "Sicherheits-Signaturen nie aktualisiert", "Updates", "HIGH", "fortinet", "regex",
              r"^Virus-DB: 1\.00000",
              "FortiGuard-Updates aktivieren und Signaturen (AV, IPS) aktualisieren"),
]


# Die eigentliche Konfiguration kommt zuerst, wie beim Collector. Steht sie mitten zwischen
# den anderen Ausgaben, übersieht llama3.1:8b darin deutlich mehr.
CONFIG_FILES = ("show_running_config", "show", "show_full_configuration")


def read_outputs(folder: Path) -> list[tuple[str, str]]:
    """gns3_output/<Gerät>/show_running_config.txt -> ("show running config", Inhalt)"""
    files = sorted(folder.glob("*.txt"), key=lambda f: (f.stem not in CONFIG_FILES, f.stem))
    return [(f.stem.replace("_", " "), f.read_text(encoding="utf-8").strip())
            for f in files if f.read_text(encoding="utf-8").strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Demo: Konfigurations-Analyse mit Ollama")
    parser.add_argument("folders", nargs="+", type=Path,
                        help="Geräte-Ordner mit .txt-Ausgaben, oder gns3_output für alle Geräte darin")
    args = parser.parse_args()
    # verworfene LLM-Antworten nicht mitten in die Ausgabe schreiben
    logging.getLogger(analyzer.__name__).setLevel(logging.ERROR)

    devices = device_folders(args.folders)
    if not devices:
        raise SystemExit("Keine .txt-Dateien gefunden.")

    results = []
    for folder in devices:
        try:
            results.append(analyze_folder(folder))
        except Exception as e:      # ein Gerät darf die Demo nicht abbrechen
            print(f"\n  {folder.name}: FEHLER ({e})\n")

    if len(devices) > 1:
        print("=== Übersicht ===")
        print(f"{'Gerät':<14}{'Bewertung':<11}{'Score':>5}  Befunde")
        for result in results:
            print(f"{result.hostname:<14}{result.rating:<11}{result.score:>5}  {len(result.findings)}")
        print()


def device_folders(paths: list[Path]) -> list[Path]:
    """Ein Ordner mit .txt-Dateien ist ein Gerät, sonst werden seine Unterordner genommen."""
    folders = []
    for path in paths:
        if any(path.glob("*.txt")):
            folders.append(path)
        else:
            folders += sorted(p for p in path.iterdir() if p.is_dir() and any(p.glob("*.txt")))
    return folders


def analyze_folder(folder: Path) -> analyzer.Assessment:
    hostname = folder.name
    sections = read_outputs(folder)
    vendor = "fortinet" if any(name.startswith("get system") for name, _ in sections) else "cisco"

    print(f"\n=== All Seeing Eye – Analyse von {hostname} ({vendor}) ===\n")
    print(f"1) {len(sections)} Befehlsausgaben gelesen ({sum(len(o) for _, o in sections):,} Zeichen)")

    raw_content = "\n".join(f"### {name}\n{output}\n" for name, output in sections)
    chunks = analyzer.prepare_llm_chunks(sections, vendor)
    secrets = sum(c.count("<entfernt>") for c in chunks)
    print(f"2) Nur die Konfiguration geht an das LLM: {sum(len(c) for c in chunks):,} Zeichen, "
          f"{secrets} Passwörter/Hashes geschwärzt")

    rules = [r for r in DEMO_RULES if analyzer.rule_applies(r, vendor)]
    local_rules = [r for r in rules if r.check_type in analyzer.LOCAL_CHECKS]
    llm_rules = [r for r in rules if r not in local_rules]
    request = analyzer.AnalysisRequest(collection_id=0, hostname=hostname, vendor=vendor, os_version="",
                                       local_rules=local_rules, llm_rules=llm_rules,
                                       raw_content=raw_content, chunks=chunks)

    local = analyzer.check_rules(raw_content, local_rules)
    print(f"3) {len(local_rules)} Regeln direkt geprüft (Regex): {len(local)} Treffer")

    print(f"4) Ollama ({settings.ollama_model} auf {settings.ollama_host}) prüft {len(llm_rules)} Regeln ...",
          end="", flush=True)
    start = time.perf_counter()
    llm = analyzer.run_llm(request)
    print(f" fertig in {time.perf_counter() - start:.1f} s: {len(llm)} Treffer")

    result = analyzer.assess(0, hostname, local + llm)
    print(f"\n=== Ergebnis: {result.rating}  (Score {result.score}/100) ===")
    for f in result.findings:
        source = "Ollama" if f.detected_by == "llm" else "Regel"
        print(f"\n  [{f.severity:<8}] {f.title}   (erkannt von: {source})")
        if f.evidence:
            print(f"     Beleg:      {f.evidence}")
        print(f"     Empfehlung: {f.recommendation}")
    if not result.findings:
        print("\n  Keine Befunde.")
    print()
    return result


if __name__ == "__main__":
    main()
