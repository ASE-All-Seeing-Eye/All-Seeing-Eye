from fastapi import APIRouter
from all_seeing_eye.database.repository import list_devices, list_interfaces, list_connections

router = APIRouter(prefix="/api/topology", tags=["Topologie"])


@router.get("")
def get_topology():
    devices = list_devices()

    interface_namen = {}
    for device in devices:
        for interface in list_interfaces(device["id"]):
            interface_namen[interface["id"]] = interface["name"]

    nodes = []
    for device in devices:
        nodes.append({
            "data": {
                "id": str(device["id"]),
                "label": device["hostname"] or str(device["management_ip"]),
                "vendor": device["vendor"],
                "ip": str(device["management_ip"]),
            }
        })

    edges = []
    schon_gesehen = set()

    for connection in list_connections():
        if connection["target_device_id"] is None:
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