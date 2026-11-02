"""Die Sicherheitsregeln von All Seeing Eye. Der Analyzer liest sie aus der Tabelle securityrule, von hier kommen sie hinein.

Fehlende Regeln eintragen (im Ordner backend), vorhandene bleiben unverändert:
    uv run python -m all_seeing_eye.analysis.rules
"""
from sqlalchemy import select
from sqlalchemy.orm import Session

from all_seeing_eye.database.models import SecurityRule
from all_seeing_eye.database.session import SessionFactory

_RULES = [
    # ---- werden von Ollama geprüft ----
    ("LLM-01", "Unverschlüsselte Verwaltung (Telnet/HTTP)", "Management", "HIGH", "all", "llm",
     "Telnet oder HTTP ohne s ist als Verwaltungszugang erlaubt (z. B. 'transport input telnet', "
     "'ip http server', 'set allowaccess ... http' oder '... telnet', 'set admin-telnet enable'). "
     "Reine Portnummern wie 'set admin-port 80' oder 'admin-telnet-port 23' sind kein Verstoß",
     "Nur SSH und HTTPS für die Verwaltung erlauben"),
    ("LLM-02", "SNMP mit Standard-Community", "Management", "CRITICAL", "all", "llm",
     "SNMP-Community heißt 'public' oder 'private'",
     "Eigene Community bzw. SNMPv3 verwenden"),

    # ---- werden direkt in Python geprüft: alle Hersteller ----
    ("GEN-01", "Standard-Administratorkonto 'admin'", "Authentifizierung", "MEDIUM", "all", "regex",
     r'^username admin\b|(?<=config system admin\n)\s*edit "admin"',
     "Personalisierte Admin-Konten anlegen und 'admin' deaktivieren"),
    ("GEN-02", "Kein externer Syslog-Server", "Logging", "MEDIUM", "all", "not_regex",
     r"^logging host|config log syslogd setting\s*\n(\s+set .*\n)*?\s+set status enable",
     "Logs an einen zentralen Syslog-Server senden"),
    ("GEN-03", "Kein Login-Banner", "Management", "LOW", "all", "not_regex",
     r"^banner (login|motd)|set pre-login-banner enable",
     "Login-Banner mit rechtlichem Hinweis konfigurieren"),

    # ---- Cisco IOS ----
    ("CIS-01", "Passwörter im Klartext oder mit Typ 7", "Authentifizierung", "HIGH", "cisco", "regex",
     r"^enable password|^username \S+ .*password (0|7) ",
     "'enable secret' bzw. 'username ... secret' (Typ 8/9) verwenden"),
    ("CIS-02", "Keine Passwort-Verschlüsselung (service password-encryption)", "Authentifizierung",
     "LOW", "cisco", "not_regex", r"^service password-encryption",
     "'service password-encryption' aktivieren"),
    ("CIS-03", "Kein AAA (zentrale Authentifizierung)", "Authentifizierung", "MEDIUM", "cisco",
     "regex", r"^no aaa new-model",
     "AAA aktivieren und Anmeldung über RADIUS/TACACS+ führen"),
    ("CIS-04", "Kein Schutz gegen Brute-Force-Anmeldungen", "Authentifizierung", "MEDIUM", "cisco",
     "not_regex", r"^login block-for",
     "'login block-for ... attempts ... within ...' konfigurieren"),
    ("CIS-05", "VTY-Zugriff nicht per ACL eingeschränkt", "Management", "MEDIUM", "cisco",
     "not_regex", r"^\s*access-class \S+ in",
     "Auf den VTY-Leitungen eine 'access-class' mit erlaubten Management-IPs setzen"),
    ("CIS-06", "Kein NTP-Server", "Logging", "LOW", "cisco", "not_regex", r"^ntp server",
     "NTP-Server konfigurieren, damit Logs korrekte Zeitstempel haben"),
    ("CIS-07", "SSH Version 1 erlaubt", "Protokolle", "HIGH", "cisco", "not_regex", r"^ip ssh version 2",
     "'ip ssh version 2' setzen"),
    ("CIS-08", "Kein Session-Timeout", "Management", "MEDIUM", "cisco", "regex", r"exec-timeout 0( 0)?$",
     "'exec-timeout 10 0' oder kürzer setzen"),
    ("CIS-09", "CDP aktiv (verrät Geräteinformationen)", "Protokolle", "LOW", "cisco", "regex",
     r"^Device ID|Total cdp entries displayed",
     "CDP auf Interfaces zu nicht vertrauenswürdigen Netzen deaktivieren"),

    # ---- FortiGate ----
    ("FGT-01", "Admin-Zugriff nicht auf vertrauenswürdige Hosts beschränkt", "Management", "MEDIUM",
     "fortinet", "not_regex", r"set trusthost\d+ (?!0\.0\.0\.0 0\.0\.0\.0)",   # 0.0.0.0 = Standard, alles erlaubt
     "Beim Admin-Konto 'set trusthost1 <Management-Netz>' setzen"),
    ("FGT-02", "Keine Passwort-Richtlinie für Admins", "Authentifizierung", "MEDIUM", "fortinet",
     "not_regex", r"config system password-policy\s*\n(\s+set .*\n)*?\s+set status enable",
     "'config system password-policy' mit Mindestlänge und Komplexität aktivieren"),
    ("FGT-03", "Lokales Gastkonto vorhanden", "Authentifizierung", "LOW", "fortinet", "regex",
     r'^\s*edit "guest"$', "Nicht benötigte lokale Konten entfernen"),
    ("FGT-04", "Sicherheits-Signaturen nie aktualisiert", "Updates", "HIGH", "fortinet", "regex",
     r"^Virus-DB: 1\.00000",
     "FortiGuard-Updates aktivieren und Signaturen (AV, IPS) aktualisieren"),
]


def security_rules() -> list[SecurityRule]:
    """Jeder Aufruf gibt neue Objekte zurück, die noch zu keiner Session gehören."""
    return [SecurityRule(code=code, title=title, category=category, severity=severity, vendor=vendor,
                         check_type=check_type, check_value=check_value, recommendation=recommendation,
                         source="All Seeing Eye")
            for code, title, category, severity, vendor, check_type, check_value, recommendation in _RULES]


def add_missing_rules(session: Session) -> list[str]:
    """Trägt fehlende Regeln ein und gibt ihre Codes zurück. Vorhandene Regeln werden nie überschrieben."""
    existing = set(session.scalars(select(SecurityRule.code)))
    missing = [rule for rule in security_rules() if rule.code not in existing]
    session.add_all(missing)
    session.commit()
    return [rule.code for rule in missing]


def main() -> None:
    with SessionFactory() as session:
        added = add_missing_rules(session)
    print(f"{len(added)} Regeln eingetragen: {', '.join(added)}" if added else "Alle Regeln sind schon eingetragen.")


if __name__ == "__main__":
    main()
