
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from netmiko import ConnectHandler
from netmiko.exceptions import (NetmikoAuthenticationException,
                                NetmikoTimeoutException)

try:
    from .models import Device, RawConfig
except ImportError:
    from models import Device, RawConfig

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("collector.audit")



class SSHAuthenticationError(Exception):
    """Benutzername oder Passwort falsch."""


class SSHUnreachableError(Exception):
    """Gerät nicht erreichbar (Timeout)."""


class SSHConnectionClosedError(Exception):
    """Gerät nimmt die Verbindung an, schließt sie aber sofort wieder (z. B. SSH auf den vty-Leitungen nicht erlaubt)."""


@dataclass
class ConnectionSettings:
    retries: int = 2
    retry_delay: float = 3.0
    timeout: int = 15
    strict_host_key: bool = False
    allow_telnet: bool = False


def open_connection(device: Device, settings: ConnectionSettings | None = None):
    """Öffnet eine SSH-Verbindung (Telnet nur mit allow_telnet=True) und gibt das Netmiko-Objekt zurück."""
    settings = settings or ConnectionSettings()

    params = {k: v for k, v in asdict(device).items() if v is not None}
    if settings.allow_telnet:
        logger.warning("%s: Telnet erlaubt (unverschlüsselt, nur im Lab verwenden)", device.host)
    else:
        params["device_type"] = params["device_type"].replace("_telnet", "")
    params.update(
        conn_timeout=settings.timeout,
        auth_timeout=settings.timeout,
        banner_timeout=settings.timeout,
        ssh_strict=settings.strict_host_key,
        system_host_keys=settings.strict_host_key,
    )

    last_error: Exception | None = None
    closed_by_device = False
    for attempt in range(1, settings.retries + 2):
        try:
            return ConnectHandler(**params)
        except NetmikoAuthenticationException as e:

            raise SSHAuthenticationError(f"{device.host}: Authentifizierung fehlgeschlagen") from e
        except NetmikoTimeoutException as e:
            last_error = e
            # "Error reading SSH protocol banner": TCP steht, das Gerät schließt sofort wieder
            closed_by_device = "banner" in str(e).lower()
            logger.warning("%s: Timeout (Versuch %d)", device.host, attempt)
            if attempt <= settings.retries:
                time.sleep(settings.retry_delay * attempt)

    if closed_by_device:
        raise SSHConnectionClosedError(f"{device.host}: Gerät hat die SSH-Verbindung sofort geschlossen") from last_error
    raise SSHUnreachableError(f"{device.host}: Gerät nicht erreichbar") from last_error



ALLOWED_COMMANDS = (
    "show running-config",
    "show startup-config",
    "show version",
    "show inventory",
    "show clock",
    "show users",
    "show logging",
    "show privilege",
    "show snmp",
    "show ntp",
    "show ip ssh",
    "show ip interface brief",
    "show ip route",
    "show ip protocols",
    "show ip ospf",
    "show ip arp",
    "show ip access-lists",
    "show access-lists",
    "show interfaces",
    "show vlan",
    "show mac address-table",
    "show spanning-tree",
    "show cdp neighbors",
    "show lldp neighbors",
)

ALLOWED_FILTERS = ("include", "exclude", "section", "begin")

DEFAULT_COMMANDS = ("show running-config", "show version", "show cdp neighbors")

FORTINET_ALLOWED_COMMANDS = ("show", "get")
FORTINET_ALLOWED_FILTERS = ("grep",)

FORTINET_DEFAULT_COMMANDS = (
    "get system status",
    "show",
    "get system interface physical",
    "get router info routing-table all",
    "get router info ospf neighbor",
    "get system arp",
    "get system admin list",
    "get system performance status",
)

DEFAULT_COMMANDS_BY_VENDOR = {
    "cisco": DEFAULT_COMMANDS,
    "fortinet": FORTINET_DEFAULT_COMMANDS,
}


def vendor_of(device_type: str) -> str:
    """Leitet aus dem Netmiko-Gerätetyp den Hersteller ab ('cisco' oder 'fortinet')."""
    return "fortinet" if device_type.lower().startswith(("fortinet", "fortios")) else "cisco"


CONSOLE_PROMPT = r"\S+#\s*$"


@dataclass
class CollectionResult:
    host: str
    port: int | None = None
    prompt: str | None = None
    hostname: str | None = None
    outputs: dict[str, RawConfig] = field(default_factory=dict)
    error: str | None = None
    started_at: str = ""
    duration_s: float = 0.0

    @property
    def success(self) -> bool:
        return self.error is None and all(r.error is None for r in self.outputs.values())


class ConfigCollector:
    def __init__(self, max_workers: int = 10, read_timeout: int = 60,
                 settings: ConnectionSettings | None = None):
        self.max_workers = max_workers
        self.read_timeout = read_timeout
        self.settings = settings or ConnectionSettings()

    @staticmethod
    def is_allowed(command: str, vendor: str = "cisco") -> bool:
        """Prüft, ob ein Befehl in der Whitelist steht und keine Tricks enthält."""
        if any(c in command for c in ("\n", "\r", ";")):
            return False
        if vendor == "fortinet":
            allowed_commands, allowed_filters = FORTINET_ALLOWED_COMMANDS, FORTINET_ALLOWED_FILTERS
        else:
            allowed_commands, allowed_filters = ALLOWED_COMMANDS, ALLOWED_FILTERS
        base, *filters = [p.strip().lower() for p in command.split("|")]
        base = " ".join(base.split())
        if not any(base == a or base.startswith(a + " ") for a in allowed_commands):
            return False
        return all(f.startswith(allowed_filters) for f in filters)

    @staticmethod
    def _audit(host: str, command: str, status: str) -> None:
        audit_logger.info("time=%s host=%s command=%r status=%s",
                          datetime.now(timezone.utc).isoformat(), host, command, status)


    def collect_device(self, device: Device,
                       commands: tuple[str, ...] | list[str] | dict | None = None) -> CollectionResult:
        """commands: None = Standardbefehle des Herstellers, Liste = für dieses Gerät,
        Dictionary = Befehle je Hersteller, z. B. {"cisco": [...], "fortinet": [...]}."""
        start = time.monotonic()
        label = f"{device.host}:{device.port}"
        vendor = vendor_of(device.device_type)
        if commands is None:
            commands = DEFAULT_COMMANDS_BY_VENDOR[vendor]
        elif isinstance(commands, dict):
            commands = commands.get(vendor, DEFAULT_COMMANDS_BY_VENDOR[vendor])
        result = CollectionResult(host=device.host, port=device.port,
                                  started_at=datetime.now(timezone.utc).isoformat())

        allowed = []
        for cmd in commands:
            if self.is_allowed(cmd, vendor):
                allowed.append(cmd)
            else:
                result.outputs[cmd] = RawConfig(host=device.host, error="Befehl nicht erlaubt")
                self._audit(label, cmd, "BLOCKED")

        console = self.settings.allow_telnet and device.device_type.endswith("_telnet")

        if allowed:
            try:
                with open_connection(device, self.settings) as conn:
                    if console:
                        time.sleep(1)
                        conn.clear_buffer()
                    if device.secret and vendor == "cisco":
                        conn.enable()
                    if console:
                        conn.clear_buffer()
                    result.prompt = conn.find_prompt()
                    kwargs = {"read_timeout": self.read_timeout}
                    if console:
                        kwargs["expect_string"] = CONSOLE_PROMPT
                    for cmd in allowed:
                        try:
                            output = conn.send_command(cmd, **kwargs)
                            result.outputs[cmd] = RawConfig(host=device.host, config=output)
                            self._audit(label, cmd, "OK")
                        except Exception as e:
                            msg = str(e).strip()
                            result.outputs[cmd] = RawConfig(
                                host=device.host,
                                error=msg.splitlines()[0] if msg else type(e).__name__)
                            self._audit(label, cmd, "ERROR")
            except SSHAuthenticationError:
                result.error = "Authentifizierung fehlgeschlagen"
                self._audit(label, "-", "AUTH_FAILED")
            except SSHConnectionClosedError:
                result.error = ("SSH-Verbindung vom Gerät sofort geschlossen (vty-Leitungen prüfen: "
                                "transport input ssh, login local; evtl. alle Leitungen belegt)")
                self._audit(label, "-", "CONNECTION_CLOSED")
            except SSHUnreachableError:
                result.error = "Timeout: Gerät nicht erreichbar"
                self._audit(label, "-", "TIMEOUT")
            except Exception as e:
                result.error = f"Unerwarteter Fehler: {str(e).strip().splitlines()[0] if str(e).strip() else type(e).__name__}"
                self._audit(label, "-", "ERROR")

        self._set_hostname(result, vendor)
        result.duration_s = round(time.monotonic() - start, 2)
        return result

    @staticmethod
    def _set_hostname(result: CollectionResult, vendor: str = "cisco") -> None:
        """Liest den Hostnamen aus der Config (oder Statusausgabe) und korrigiert den Prompt."""
        if vendor == "fortinet":
            patterns = (("get system status", r"^Hostname\s*:\s*(\S+)"),
                        ("show", r'^\s*set hostname "?([^"\s]+)"?'))
            suffix = " #"
        else:
            patterns = (("show running-config", r"^hostname\s+(\S+)"),
                        ("show version", r"^(\S+)\s+uptime is"))
            suffix = "#"
        for cmd, pattern in patterns:
            raw = result.outputs.get(cmd)
            if raw and raw.config:
                match = re.search(pattern, raw.config, re.MULTILINE)
                if match:
                    result.hostname = match.group(1)
                    result.prompt = f"{result.hostname}{suffix}"
                    return

    def collect_many(self, devices: list[Device],
                     commands: tuple[str, ...] | list[str] | dict | None = None) -> list[CollectionResult]:
        """Mehrere Geräte parallel abfragen."""
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = [pool.submit(self.collect_device, d, commands) for d in devices]
            for future in as_completed(futures):
                results.append(future.result())
        return results

    def send_command(self, device: Device, command: str) -> RawConfig:
        result = self.collect_device(device, [command])
        if result.error:
            return RawConfig(host=device.host, error=result.error)
        return result.outputs[command]

    def get_prompt(self, device: Device) -> str:
        return self.collect_device(device, ["show version"]).prompt or ""

    def get_config(self, device: Device) -> RawConfig:
        return self.send_command(device, "show running-config")

    def get_cdp_neighbors(self, device: Device) -> RawConfig:
        return self.send_command(device, "show cdp neighbors")

    def get_version(self, device: Device) -> RawConfig:
        return self.send_command(device, "show version")