from fastapi import APIRouter
from all_seeing_eye.database.repository import list_devices

router = APIRouter(prefix="/api/inventory", tags=["Inventar"])

@router.get("")
def get_inventory():
    return list_devices()