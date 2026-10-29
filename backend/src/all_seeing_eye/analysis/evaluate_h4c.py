"""Nachweis H4c/H6b: mindestens 8 von 10 Fehlern erkannt, höchstens 1 Fehlalarm bei 5 sauberen Configs.

Start (im Ordner backend):
    uv run python -m all_seeing_eye.analysis.evaluate_h4c             # mit LLM, ca. 1 Stunde
    uv run python -m all_seeing_eye.analysis.evaluate_h4c --ohne-llm  # nur Regex, ohne UCS
"""
import json
import logging
import sys
from pathlib import Path

from all_seeing_eye.analysis import analyzer
from all_seeing_eye.analysis.demo import DEMO_RULES

DATA_DIR = Path(__file__).resolve().parents[3] / "tests" / "data" / "h4c"


def find_rules(path: Path, use_llm: bool) -> set[str]:
    """Analysiert eine Config-Datei und gibt die Codes der gefundenen Regeln zurück."""
    vendor = "fortinet" if path.name.startswith("forti") else "cisco"
    config = path.read_text(encoding="utf-8")
    rules = [r for r in DEMO_RULES if analyzer.rule_applies(r, vendor)]
    regex_rules = [r for r in rules if r.check_type in analyzer.LOCAL_CHECKS]
    llm_rules = [r for r in rules if r not in regex_rules] if use_llm else []
    request = analyzer.AnalysisRequest(0, path.stem, vendor, "", regex_rules, llm_rules, config,
                                       analyzer.prepare_llm_chunks([("show", config)], vendor))
    return {f.rule.code for f in analyzer.check_rules(config, regex_rules) + analyzer.run_llm(request)}


def main() -> None:
    use_llm = "--ohne-llm" not in sys.argv
    logging.getLogger(analyzer.__name__).setLevel(logging.ERROR)
    expected = json.loads((DATA_DIR / "expected.json").read_text(encoding="utf-8"))
    detected = false_alarms = 0

    for path in sorted(DATA_DIR.glob("*/*.txt")):
        rule = expected[path.name]["regel"]
        if rule and rule.startswith("LLM") and not use_llm:
            print(f"{path.name:<32} übersprungen (braucht LLM)")
            continue
        found = find_rules(path, use_llm)
        if rule:                                   # fehlerhafte Config: Fehler muss gefunden werden
            detected += rule in found
            print(f"{path.name:<32} {'erkannt' if rule in found else 'NICHT erkannt'}")
        else:                                      # saubere Config: es darf nichts gefunden werden
            false_alarms += bool(found)
            print(f"{path.name:<32} {'FEHLALARM ' + ', '.join(found) if found else 'ok'}")

    print(f"\nErkannt: {detected} von 10 (Ziel >= 8), Fehlalarme: {false_alarms} von 5 (Ziel <= 1)")
    if use_llm:
        print("BESTANDEN" if detected >= 8 and false_alarms <= 1 else "NICHT BESTANDEN")


if __name__ == "__main__":
    main()
