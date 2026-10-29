import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from all_seeing_eye.api.inventory import router as inventory_router

app = FastAPI(title="All Seeing Eye API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

app.include_router(inventory_router)

static_dir = os.getenv("STATIC_DIR")
if static_dir and Path(static_dir).exists():
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="frontend")