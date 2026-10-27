from all_seeing_eye.parser.base import Parser
from all_seeing_eye.parser.normalize import detect_os_type, same_interface
from all_seeing_eye.parser.cisco import CiscoParser
from all_seeing_eye.parser.fortinet import FortiParser
from all_seeing_eye.database import repository as db

def get_parser(commands: dict[str, str]) -> Parser | None:
    output = commands.get("show version") or commands.get("get system status") or ""
    os_type = detect_os_type(output)
    if os_type in ["ios", "ios_xe", "nx_os"]:
        return CiscoParser(os_type)
    if os_type == "fortios":
        return FortiParser()
    return None

def resolve_connections() -> None:
    for connection in db.list_unresolved_connections():
        if not connection["remote_hostname"] or not connection["remote_interface"]:
            continue
        device = db.get_device_by_hostname(connection["remote_hostname"])
        if device is None:
            continue
        for interface in db.list_interfaces(device["id"]):
            if same_interface(interface["name"], connection["remote_interface"]):
                db.create_or_update_connection(
                    source_interface_id=connection["source_interface_id"],
                    method=connection["method"],
                    remote_hostname=connection["remote_hostname"],
                    remote_interface=connection["remote_interface"],
                    target_interface_id=interface["id"]
                )
                break

def process_collection(collection_id: int) -> None:
    collection = db.get_collection(collection_id)
    if collection is None:
        raise ValueError(f"Collection {collection_id} existiert nicht")
    device = db.get_device(collection["device_id"])
    command_rows = db.get_commands_of_collection(collection_id)
    commands = {}
    for row in command_rows:
        commands[row["name"]] = row["output"]
    parser = get_parser(commands)
    if parser is None:
        db.log_event("parser", "parse", "collection", collection_id, "failed", "Gerätetyp nicht erkannt")
        return
    try:
        result = parser.parse(commands)
    except Exception as e:
        db.log_event("parser", "parse", "collection", collection_id, "failed", str(e))
        raise
    for row in command_rows:
        if not row["output"]:
            continue
        parsed = parser.parse_command(row["name"], row["output"])
        status = "ok" if parsed is not None else "unsupported"
        db.save_parsed_command(row["id"], parsed, status)
    device_id = db.create_or_update_device(
        management_ip=device["management_ip"],
        hostname=result.device.hostname,
        vendor=result.device.vendor,
        model=result.device.model,
        os_type=result.device.os_type,
        os_version=result.device.os_version,
    )
    interface_ids = {}
    for interface in result.interfaces:
        interface_ids[interface.name] = db.create_or_update_interface(
            device_id=device_id,
            name=interface.name,
            description=interface.description,
            ip_address=interface.ip_address,
            mac_address=interface.mac_address,
            status=interface.status,
            mode=interface.mode,
            vlan=interface.vlan
        )
    for neighbor in result.neighbors:
        source_interface_id = interface_ids.get(neighbor.local_interface)
        if source_interface_id is None:
            result.errors.append(f"{neighbor.local_interface}: Interface unbekannt, Verbindung übersprungen")
            continue
        db.create_or_update_connection(
            source_interface_id=source_interface_id,
            remote_hostname=neighbor.remote_hostname,
            remote_interface=neighbor.remote_interface,
            method=neighbor.method
        )
    if not result.interfaces and result.errors:
        status = "failed"
    elif result.errors:
        status = "partial"
    else:
        status = "ok"
    configuration = db.get_configuration_of_collection(collection_id)
    if configuration:
        db.save_parsed_configuration(configuration["id"], result.config, status)
    db.log_event("parser", "parse", "collection", collection_id, status, ";".join(result.errors) or None)