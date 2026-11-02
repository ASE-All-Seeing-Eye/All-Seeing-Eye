"""Feste Befehle zu den Empfehlungen je Regel und Hersteller (ASE-82).

Das LLM hat im Test auf der FortiGate Befehle erfunden, deshalb kommen sie von hier. Nur ein Vorschlag,
wird nie automatisch auf ein Gerät gespielt. FortiGate-Einstellungen wurden mit "show full-configuration"
von FortiOS 7.6.1 abgeglichen, die Cisco-Befehle gelten für IOS XE 17.6.
"""

COMMANDS = {
    # ---- Cisco IOS ----
    ("LLM-01", "cisco"): "line vty 0 4\n transport input ssh\nexit\nno ip http server\nip http secure-server",
    ("LLM-02", "cisco"): ("no snmp-server community public\nno snmp-server community private\n"
                          "snmp-server group <GRUPPE> v3 priv\n"
                          "snmp-server user <BENUTZER> <GRUPPE> v3 auth sha <AUTH-PASSWORT> priv aes 128 <PRIV-PASSWORT>"),
    ("GEN-01", "cisco"): ("username <NEUER-ADMIN> privilege 15 algorithm-type scrypt secret <PASSWORT>\n"
                          "! Erst mit dem neuen Konto anmelden und testen, dann (Rückfrage mit Enter bestätigen):\n"
                          "no username admin"),
    ("GEN-02", "cisco"): "logging host <SYSLOG-IP>\nlogging trap informational",
    ("GEN-03", "cisco"): "banner login # <RECHTLICHER-HINWEIS> #",
    ("CIS-01", "cisco"): ("enable algorithm-type scrypt secret <PASSWORT>\nno enable password\n"
                          "username <NAME> algorithm-type scrypt secret <PASSWORT>"),
    ("CIS-02", "cisco"): "service password-encryption",
    ("CIS-03", "cisco"): ("aaa new-model\ntacacs server <NAME>\n address ipv4 <SERVER-IP>\n key <SCHLUESSEL>\nexit\n"
                          "aaa authentication login default group tacacs+ local"),
    ("CIS-04", "cisco"): "login block-for 120 attempts 3 within 60",
    ("CIS-05", "cisco"): ("ip access-list standard MGMT\n permit <MANAGEMENT-NETZ> <WILDCARD-MASKE>\nexit\n"
                          "line vty 0 4\n access-class MGMT in"),
    ("CIS-06", "cisco"): "ntp server <NTP-IP>",
    ("CIS-07", "cisco"): "ip ssh version 2",
    ("CIS-08", "cisco"): "line vty 0 4\n exec-timeout 10 0\nline con 0\n exec-timeout 10 0",
    ("CIS-09", "cisco"): "interface <INTERFACE>\n no cdp enable",

    # ---- FortiGate ----
    ("LLM-01", "fortinet"): ("config system interface\n    edit <INTERFACE>\n        set allowaccess ping https ssh\n"
                             "    next\nend\nconfig system global\n    set admin-telnet disable\nend"),
    ("LLM-02", "fortinet"): "config system snmp community\n    delete <ID>\nend\n# Danach SNMPv3 unter 'config system snmp user' einrichten",
    ("GEN-01", "fortinet"): ("config system admin\n    edit <NEUER-ADMIN>\n        set accprofile super_admin\n"
                             "        set vdom root\n        set password <PASSWORT>\n    next\nend\n"
                             "# Erst mit dem neuen Konto anmelden und testen, dann:\n"
                             "config system admin\n    delete admin\nend"),
    ("GEN-02", "fortinet"): "config log syslogd setting\n    set status enable\n    set server <SYSLOG-IP>\nend",
    ("GEN-03", "fortinet"): ("config system replacemsg admin pre_admin-disclaimer-text\n"
                             "    set buffer \"<RECHTLICHER-HINWEIS>\"\nend\n"
                             "config system global\n    set pre-login-banner enable\nend"),
    ("FGT-01", "fortinet"): ("# Das eigene Management-Netz muss enthalten sein, sonst sperrst du dich aus\n"
                             "config system admin\n    edit <ADMIN>\n        set trusthost1 <NETZ> <MASKE>\n"
                             "    next\nend"),
    ("FGT-02", "fortinet"): ("config system password-policy\n    set status enable\n    set minimum-length 12\n"
                             "    set min-upper-case-letter 1\n    set min-lower-case-letter 1\n"
                             "    set min-number 1\n    set min-non-alphanumeric 1\nend"),
    ("FGT-03", "fortinet"): "config user local\n    delete guest\nend",
    ("FGT-04", "fortinet"): ("# Braucht eine FortiGuard-Lizenz und Internetzugang\n"
                             "config system autoupdate schedule\n    set status enable\n    set frequency daily\nend\n"
                             "execute update-now"),
}
