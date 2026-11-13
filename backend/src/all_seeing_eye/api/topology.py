from fastapi import APIRouter
from all_seeing_eye.database.repository import list_interfaces, list_connections
from all_seeing_eye.api.inventory import devices_from_last_scan

router = APIRouter(prefix="/api/topology", tags=["Topologie"])


@router.get("")
def get_topology():
    devices = devices_from_last_scan()
    device_ids = {device["id"] for device in devices}

    interface_namen = {}
    switch_geraete = set()
    for device in devices:
        for interface in list_interfaces(device["id"]):
            interface_namen[interface["id"]] = interface["name"]
            if interface["mode"] in ("access", "trunk") or interface["name"].lower().startswith("vlan"):
                switch_geraete.add(device["id"])

    nodes = []
    for device in devices:
        nodes.append({
            "data": {
                "id": str(device["id"]),
                "label": device["hostname"] or str(device["management_ip"]),
                "vendor": device["vendor"],
                "ip": str(device["management_ip"]),
                "model": device["model"],
                "os_type": device["os_type"],
                "switch": device["id"] in switch_geraete,
            }
        })

    edges = []
    schon_gesehen = set()

    for connection in list_connections():
        if connection["source_device_id"] not in device_ids or connection["target_device_id"] not in device_ids:
            continue

        schluessel = tuple(sorted([connection["source_interface_id"], connection["target_interface_id"]]))
        if schluessel in schon_gesehen:
            continue
        schon_gesehen.add(schluessel)

        edges.append({
            "data": {
                "id": f"verbindung-{connection['id']}",
                "source": str(connection["source_device_id"]),
                "target": str(connection["target_device_id"]),
                "source_interface": interface_namen.get(connection["source_interface_id"]),
                "target_interface": interface_namen.get(connection["target_interface_id"]),
                "method": connection["method"],
            }
        })

    return {"nodes": nodes, "edges": edges}