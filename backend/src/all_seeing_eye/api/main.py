import json
import os
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="All Seeing Eye API")
DEMO_REPORT_PFAD = Path(__file__).resolve().parent.parent / "report" / "report_demo.json"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

@app.get("/api/reports")
def get_demo_report():
    if not DEMO_REPORT_PFAD.exists():
        raise HTTPException(status_code=404, detail="report_demo.json nicht gefunden")
    with open(DEMO_REPORT_PFAD, encoding="utf-8") as datei:
        return json.load(datei)

static_dir = os.getenv("STATIC_DIR")
if static_dir and Path(static_dir).exists():
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="frontend")