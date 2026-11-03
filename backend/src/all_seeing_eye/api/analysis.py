from fastapi import APIRouter, HTTPException
from all_seeing_eye.database.repository import (
    list_jobs,
    get_job,
    get_findings_of_job,
    get_analyses_of_job,
    get_collections_of_job,
    get_devices_of_job,
)

router = APIRouter(prefix="/api/analysis", tags=["Analyse"])

SCHWEREGRADE = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@router.get("/jobs")
def get_jobs():
    return list_jobs()


@router.get("/jobs/{job_id}")
def get_job_analyse(job_id: int):
    job = get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} existiert nicht")

    geraete = {geraet["id"]: geraet for geraet in get_devices_of_job(job_id)}
    collection_zu_geraet = {c["id"]: c["device_id"] for c in get_collections_of_job(job_id)}
    analyse_zu_collection = {a["id"]: a["collection_id"] for a in get_analyses_of_job(job_id)}

    funde = []
    for finding in get_findings_of_job(job_id):
        collection_id = analyse_zu_collection.get(finding["analysis_id"])
        geraet = geraete.get(collection_zu_geraet.get(collection_id))

        funde.append({
            **finding,
            "severity": finding["severity"].strip().upper(),
            "device_name": (geraet["hostname"] or str(geraet["management_ip"])) if geraet else "Unbekannt",
        })

    funde.sort(key=lambda f: SCHWEREGRADE.index(f["severity"]) if f["severity"] in SCHWEREGRADE else len(SCHWEREGRADE))

    statistik = {stufe: 0 for stufe in SCHWEREGRADE}
    for fund in funde:
        if fund["severity"] in statistik:
            statistik[fund["severity"]] += 1

    return {"job": job, "findings": funde, "statistik": statistik}