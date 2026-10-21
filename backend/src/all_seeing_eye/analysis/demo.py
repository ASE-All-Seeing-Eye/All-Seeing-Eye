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
    # werden von Ollama geprüft
    demo_rule("LLM-01", "Standard-Administratorkonto", "Authentifizierung", "MEDIUM", "all", "llm",
              "Ein Benutzerkonto heißt genau 'admin' (z. B. Zeile 'username admin ...' "
              "oder 'edit \"admin\"' unter config system admin)",
              "Eigenes, personalisiertes Admin-Konto anlegen und 'admin' deaktivieren"),
    demo_rule("LLM-02", "Unverschlüsselte Verwaltung (Telnet/HTTP)", "Management", "HIGH", "all", "llm",
              "Telnet oder HTTP ohne s ist als Verwaltungszugang erlaubt (z. B. 'transport input telnet', "
              "'ip http server', 'set allowaccess ... http' oder '... telnet')",
              "Nur SSH und HTTPS für die Verwaltung erlauben"),
    demo_rule("LLM-03", "SNMP mit Standard-Community", "Management", "CRITICAL", "all", "llm",
              "SNMP-Community heißt 'public' oder 'private'",
              "Eigene Community bzw. SNMPv3 verwenden"),
    # werden direkt in Python geprüft
    demo_rule("RGX-01", "Kein externer Syslog-Server", "Logging", "MEDIUM", "all", "not_regex",
              r"^logging host|config log syslogd setting",
              "Logs an einen zentralen Syslog-Server senden"),
    demo_rule("RGX-02", "Kein Login-Banner", "Management", "LOW", "all", "not_regex",
              r"^banner (login|motd)|set pre-login-banner enable",
              "Login-Banner mit rechtlichem Hinweis konfigurieren"),
]


def read_outputs(folder: Path) -> list[tuple[str, str]]:
    """gns3_output/<Gerät>/show_running_config.txt -> ("show running config", Inhalt)"""
    return [(f.stem.replace("_", " "), f.read_text(encoding="utf-8").strip())
            for f in sorted(folder.glob("*.txt")) if f.read_text(encoding="utf-8").strip()]


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
    llm_sections = [(n, o) for n, o in sections if n.lower() not in analyzer.SKIP_SECTIONS]
    if vendor == "fortinet":
        llm_sections = [(n, analyzer.trim_fortinet_config(o) if n == "show" else o) for n, o in llm_sections]
    secrets = sum(len(analyzer._SECRET_PATTERN.findall(o)) for _, o in llm_sections)
    chunks = analyzer.chunk_sections([(n, analyzer.redact(o)) for n, o in llm_sections])
    print(f"2) {secrets} Passwörter/Hashes geschwärzt, {sum(len(c) for c in chunks):,} Zeichen gehen an das LLM")

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
