import re
import ipaddress

CISCO_INTERFACE_NAMES = {
    "gi": "GigabitEthernet", "gig": "GigabitEthernet", "gigabitethernet": "GigabitEthernet",
    "te": "TenGigabitEthernet", "ten": "TenGigabitEthernet", "tengigabitethernet": "TenGigabitEthernet",
    "fa": "FastEthernet", "fastethernet": "FastEthernet",
    "eth": "Ethernet", "et": "Ethernet", "ethernet": "Ethernet",
    "lo": "Loopback", "loopback": "Loopback",
    "vl": "Vlan", "vlan": "Vlan",
    "po": "Port-channel", "port-channel": "Port-channel",
    "mgmt": "mgmt"
}

_INTERFACE_PATTERN = re.compile(r"([A-Za-z-]+)\s*(\d.*)")

def normalize_interface_name(name: str) -> str:
    match = _INTERFACE_PATTERN.fullmatch(name.strip())
    if match is None:
        return name

    prefix, rest = match.groups()
    full = CISCO_INTERFACE_NAMES.get(prefix.lower())
    if full is None:
        return name
    return full + rest

def normalize_hostname(hostname: str | None) -> str | None:
    if not hostname:
        return None
    hostname = hostname.strip().split("(")[0]
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    return hostname.strip().split(".")[0] or None

def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    digits = re.sub(r"[^0-9a-f]", "", mac.lower())
    if len(digits) != 12:
        return None
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))

def detect_os_type(show_version: str | None) -> str | None:
    if not show_version:
        return None
    text = show_version.lower()
    if "nx-os" in text or "nexus operating system" in text:
        return "nx_os"
    if "ios xe" in text or "ios-xe" in text:
        return "ios_xe"
    if "cisco ios software" in text:
        return "ios"
    if "fortigate" in text or "fortios" in text:
        return "fortios"
    return None