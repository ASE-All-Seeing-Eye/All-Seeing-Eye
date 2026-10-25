def detect_os_type(show_version: str) -> str | None:
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