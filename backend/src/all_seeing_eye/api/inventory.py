from fastapi import APIRouter
from all_seeing_eye.database.repository import list_devices, list_jobs, get_devices_of_job

router = APIRouter(prefix="/api/inventory", tags=["Inventar"])

def devices_from_last_scan() -> list[dict]:
    for job in list_jobs():
        if job["status"] in ("ok", "partial", "done"):
            return get_devices_of_job(job["id"])
    return list_devices()

@router.get("")
def get_inventory():
    return devices_from_last_scan()