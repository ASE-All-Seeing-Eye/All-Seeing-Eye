from sqlalchemy import select
from all_seeing_eye.database.models import Job, AuditLog, Device, Connection, Report, Finding, Analysis, Collection
from all_seeing_eye.database.session import SessionFactory

def create_job(target: str) -> int:
    with SessionFactory() as session:
        job = Job(target=target, status="pending")
        session.add(job)
        session.commit()
    log_event("dashboard", "job_created", "job", job.id, "ok")
    return job.id

def set_job_status(job_id: int, status: str, error: str | None = None) -> None:
    with SessionFactory() as session:
        job = session.get(Job, job_id)
        job.status = status
        job.error_message = error
        session.commit()

def get_job(job_id: int) -> dict | None:
    with SessionFactory() as session:
        job = session.get(Job, job_id)
        data = job.to_dict()
        data["has_report"] = job.report is not None
        return data

def create_or_update_device(management_ip: str, hostname: str | None = None,
                            vendor: str | None = None, model: str | None = None,
                            os_type: str | None = None, os_version: str | None = None) -> int:
    with SessionFactory() as session:
        device = session.scalar(select(Device).where(Device.management_ip == management_ip))
        if device is None:
            device = Device(management_ip=management_ip)
            session.add(device)

        if hostname is not None:
            device.hostname = hostname
        if vendor is not None:
            device.vendor = vendor
        if model is not None:
            device.model = model
        if os_type is not None:
            device.os_type = os_type
        if os_version is not None:
            device.os_version = os_version

        session.commit()
        return device.id

def get_device(management_ip: str) -> dict | None:
    with SessionFactory() as session:
        device = session.scalar(select(Device).where(Device.management_ip == management_ip))
        return device.to_dict() if device else None

def list_devices() -> list[dict]:
    with SessionFactory() as session:
        devices = session.scalars(select(Device)).all()
        return [device.to_dict() for device in devices]

def save_report(job_id: int, content: str) -> int:
    with SessionFactory() as session:
        job = session.get(Job, job_id)
        if job is None:
            raise ValueError(f"Job {job_id} existiert nicht")
        if job.report is not None:
            raise ValueError(f"Job {job.id} hat schon einen Bericht")
        report = Report(job_id=job_id, content=content)
        session.add(report)
        session.commit()
        return report.id

def get_report(job_id: int) -> dict | None:
    with SessionFactory() as session:
        report = session.scalar(select(Report).where(Report.job_id == job_id))
        return report.to_dict() if report else None

def get_devices_of_job(job_id: int) -> list[dict]:
    with SessionFactory() as session:
        statement = (
            select(Device, Collection.status)
            .join(Collection, Collection.device_id == Device.id)
            .where(Collection.job_id == job_id)
        )
        result = []
        for device, status in session.execute(statement).all():
            data = device.to_dict()
            data["collection_status"] = status
            result.append(data)
        return result

def add_finding(analysis_id: int, detected_by: str, title: str, category: str, severity: str, 
                description: str, reason: str, recommendation: str, evidence: str | None = None,
                rule_id: int | None = None) -> int:
    with SessionFactory() as session:
        finding = Finding(analysis_id=analysis_id, rule_id=rule_id, detected_by=detected_by,
                          title=title, category=category, severity=severity,
                          description=description, reason=reason,
                          recommendation=recommendation, evidence=evidence)
        session.add(finding)
        session.commit()
        return finding.id

def get_finding(finding_id: int) -> dict | None:
    with SessionFactory() as session:
        finding = session.get(Finding, finding_id)
        return finding.to_dict() if finding else None

def get_findings_of_analysis(analysis_id: int) -> list[dict]:
    with SessionFactory() as session:
        statement = select(Finding).where(Finding.analysis_id == analysis_id)
        return [f.to_dict() for f in session.scalars(statement).all()]

def get_findings_of_device(device_id: int) -> list[dict]:
    with SessionFactory() as session:
        statement = (select(Finding)
                     .join(Analysis, Finding.analysis_id == Analysis.id)
                     .join(Collection, Analysis.collection_id == Collection.id)
                     .where(Collection.device_id == device_id)
        )
        return [f.to_dict() for f in session.scalars(statement).all()]

def log_event(actor: str, action: str, object_type: str, object_id: int | None, result: str, message: str | None) -> None:
    with SessionFactory() as session:
        log = AuditLog(actor=actor, action=action, object_type=object_type, object_id=object_id, result=result, message=message)
        session.add(log)
        session.commit()
