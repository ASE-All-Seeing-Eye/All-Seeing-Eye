from sqlalchemy import select
from all_seeing_eye.database.models import *
from all_seeing_eye.database.session import SessionFactory
from datetime import datetime, timezone

JOB_STATUSES = {"pending", "running", "completed", "failed"}

def create_job(target: str) -> int:
    with SessionFactory() as session:
        job = Job(target=target, status="pending")
        session.add(job)
        session.commit()
    log_event("dashboard", "job_created", "job", job.id, "ok")
    return job.id

def get_next_pending_job() -> int | None:
    with SessionFactory() as session:
        job = session.scalar(select(Job).where(Job.status == "pending").order_by(Job.created_at).limit(1))
        return job.id if job else None

def set_job_status(job_id: int, status: str, error: str | None = None) -> None:
    if status not in JOB_STATUSES:
        raise ValueError(f"Ungültiger Status: {status}")
    
    with SessionFactory() as session:
        job = session.get(Job, job_id)
        if job is None:
            raise ValueError(f"Job {job_id} existiert nicht")
        
        job.status = status
        job.error_message = error
        if status in {"completed", "failed"}:
            job.finished_at = datetime.now(timezone.utc)
        session.commit()
    if status in {"completed", "failed"}:
        log_event("worker", "job_finished", "job", job_id, "ok" if status == "completed" else "failed", error)

def get_job(job_id: int) -> dict | None:
    with SessionFactory() as session:
        job = session.get(Job, job_id)
        if job is None:
            return None
        data = job.to_dict()
        data["has_report"] = job.report is not None
        return data

def list_jobs() -> list[dict]:
    with SessionFactory() as session:
        statement = select(Job).order_by(Job.created_at.desc())
        return [job.to_dict() for job in session.scalars(statement).all()]

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

def get_device_by_management_ip(management_ip: str) -> dict | None:
    with SessionFactory() as session:
        device = session.scalar(select(Device).where(Device.management_ip == management_ip))
        return device.to_dict() if device else None

def get_device(device_id: int) -> dict | None:
    with SessionFactory() as session:
        device = session.get(Device, device_id)
        return device.to_dict() if device else None

def get_device_by_hostname(hostname: str) -> dict | None:
    with SessionFactory() as session:
        device = session.scalar(select(Device).where(func.lower(Device.hostname) == hostname.lower())) 
        return device.to_dict() if device else None

def list_devices() -> list[dict]:
    with SessionFactory() as session:
        devices = session.scalars(select(Device)).all()
        return [device.to_dict() for device in devices]

def create_or_update_interface(device_id: int, name: str, description: str | None = None,
                               ip_address: str | None = None, mac_address: str | None = None,
                               status: str | None = None, mode: str | None = None,
                               vlan: int | None = None) -> int:
    with SessionFactory() as session:
        interface = session.scalar(select(Interface).where(Interface.device_id == device_id, Interface.name == name))
        if interface is None:
            interface = Interface(device_id=device_id, name=name)
            session.add(interface)

        if description is not None:
            interface.description = description
        if ip_address is not None:
            interface.ip_address = ip_address
        if mac_address is not None:
            interface.mac_address = mac_address
        if status is not None:
            interface.status = status
        if mode is not None:
            interface.mode = mode
        if vlan is not None:
            interface.vlan = vlan

        session.commit()
        return interface.id

def list_interfaces(device_id: int) -> list[dict]:
    with SessionFactory() as session:
        statement = select(Interface).where(Interface.device_id == device_id).order_by(Interface.name)
        return [interface.to_dict() for interface in session.scalars(statement).all()]

def create_or_update_connection(source_interface_id: int, method: str, remote_hostname: str | None = None, 
                                remote_interface: str | None = None, target_interface_id: int | None = None) -> int:
    with SessionFactory() as session:
        connection = session.scalar(select(Connection).where(
            Connection.source_interface_id == source_interface_id,
            Connection.method == method,
            Connection.remote_hostname == remote_hostname,
            Connection.remote_interface == remote_interface
            )
        )
        if connection is None:
            connection = Connection(source_interface_id=source_interface_id, method=method,
                                    remote_hostname=remote_hostname, remote_interface=remote_interface)
            session.add(connection)
        if target_interface_id is not None:
            connection.target_interface_id = target_interface_id
        session.commit()
        return connection.id

def list_connections() -> list[dict]:
    with SessionFactory() as session:
        result = []
        for connection in session.scalars(select(Connection)).all():
            data = connection.to_dict()
            data["source_device_id"] = connection.source_interface.device_id
            data["target_device_id"] = (connection.target_interface.device_id if connection.target_interface else None)
            result.append(data)
        return result

def list_unresolved_connections() -> list[dict]:
    with SessionFactory() as session:
        statement = select(Connection).where(Connection.target_interface_id.is_(None))
        return [connection.to_dict() for connection in session.scalars(statement).all()]

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

def create_scan(job_id: int) -> int:
    with SessionFactory() as session:
        scan = Scan(job_id=job_id, status="running")
        session.add(scan)
        session.commit()
        return scan.id

def get_scan(scan_id: int) -> dict | None:
    with SessionFactory() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return None
        data = scan.to_dict()
    data["scanned_hosts"] = get_hosts_of_scan(scan_id=scan_id)
    return data

def add_scan_host(scan_id: int, ip_address: str, open_tcp_ports: list[int] | None = None, open_udp_ports: list[int] | None = None,
                   device_id: int | None = None) -> int:
    with SessionFactory() as session:
        scan_host = ScanHost(scan_id=scan_id, ip_address=ip_address, device_id=device_id, open_tcp_ports=open_tcp_ports, open_udp_ports=open_udp_ports)
        session.add(scan_host)
        session.commit()
        return scan_host.id

def finish_scan(scan_id: int, status: str) -> None:
    with SessionFactory() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise ValueError(f"Scan {scan_id} existiert nicht")
        scan.status = status
        scan.finished_at = datetime.now(timezone.utc)
        session.commit()

def get_hosts_of_scan(scan_id: int) -> list[dict]:
    with SessionFactory() as session:
        statement = select(ScanHost).where(ScanHost.scan_id == scan_id)
        return [host.to_dict() for host in session.scalars(statement).all()]

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

def create_collection(device_id: int, job_id: int) -> int:
    with SessionFactory() as session:
        collection = Collection(device_id=device_id, job_id=job_id, status="running")
        session.add(collection)
        session.commit()
        return collection.id

def get_collection(collection_id: int) -> dict | None:
    with SessionFactory() as session:
        collection = session.get(Collection, collection_id)
        return collection.to_dict() if collection else None

def finish_collection(collection_id: int, status: str, error: str | None = None) -> None:
    if status not in {"ok", "partial", "failed"}:
        raise ValueError(f"Ungültiger Status: {status}")

    with SessionFactory() as session:
        collection = session.get(Collection, collection_id)
        if collection is None:
            raise ValueError(f"Collection {collection_id} existiert nicht")
        collection.status = status
        collection.error_message = error
        session.commit()

    if status == "failed":
        log_event("collector", "device_login", "device", collection.device_id, "failed", error)

def get_collections_of_job(job_id: int) -> list[dict]:
    with SessionFactory() as session:
        statement = select(Collection).where(Collection.job_id == job_id)
        return [collection.to_dict() for collection in session.scalars(statement).all()] 

def save_configuration(collection_id: int, content: str) -> int:
    with SessionFactory() as session:
        configuration = Configuration(collection_id=collection_id, content=content, parse_status="pending")
        session.add(configuration)
        session.commit()
        return configuration.id

def save_parsed_configuration(configuration_id: int, parsed: dict | None, parse_status: str,
                              error: str | None = None) -> None:
    with SessionFactory() as session:
        configuration = session.get(Configuration, configuration_id)
        if configuration is None:
            raise ValueError(f"Configuration {configuration_id} existiert nicht")
        configuration.parsed = parsed
        configuration.parse_status = parse_status
        configuration.error_message = error
        session.commit()

def get_configuration_of_collection(collection_id: int) -> dict | None:
    with SessionFactory() as session:
        statement = select(Configuration).where(Configuration.collection_id == collection_id)
        configuration = session.scalar(statement)
        return configuration.to_dict() if configuration else None

def save_command(collection_id: int, name: str, output: str | None = None, error: str | None = None) -> int:
    with SessionFactory() as session:
        command = Command(collection_id=collection_id, name=name, output=output, parse_status="pending", error_message=error)
        session.add(command)
        session.commit()
        return command.id

def save_parsed_command(command_id: int, parsed: dict | None, parse_status: str,
                        error: str | None = None) -> None:
    with SessionFactory() as session:
        command = session.get(Command, command_id)
        if command is None:
            raise ValueError(f"Command {command_id} existiert nicht")
        command.parsed = parsed
        command.parse_status = parse_status
        command.error_message = error
        session.commit()

def get_commands_of_collection(collection_id: int) -> list[dict]:
    with SessionFactory() as session:
        statement = select(Command).where(Command.collection_id == collection_id)
        return [command.to_dict() for command in session.scalars(statement).all()]

def create_analysis(collection_id: int, method: str, ai_model: str | None = None) -> int:
    if method not in {"rule", "llm", "both"}:
        raise ValueError(f"Ungültige Methode: {method}")
    
    with SessionFactory() as session:
        analysis = Analysis(collection_id=collection_id, method=method, ai_model=ai_model, status="running")
        session.add(analysis)
        session.commit()
        return analysis.id

def finish_analysis(analysis_id: int, status: str, error: str | None = None) -> None:
    if status not in {"completed", "failed"}:
        raise ValueError(f"Ungültiger Status: {status}")
    
    with SessionFactory() as session:
        analysis = session.get(Analysis, analysis_id)
        if analysis is None:
            raise ValueError(f"Analysis {analysis_id} existiert nicht")
        analysis.status = status
        analysis.error_message = error
        analysis.finished_at = datetime.now(timezone.utc)
        session.commit()

    if status == "failed":
        log_event("analyzer", "analysis_failed", "analysis", analysis_id, "failed", error)


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

def get_findings_of_job(job_id) -> list[dict]:
    with SessionFactory() as session:
        statement = (select(Finding)
                     .join(Analysis, Finding.analysis_id == Analysis.id)
                     .join(Collection, Analysis.collection_id == Collection.id)
                     .where(Collection.job_id == job_id)
        )
        return [f.to_dict() for f in session.scalars(statement).all()]

def create_securityrule(code: str, title: str, category: str, severity: str, vendor: str, check_type: str, 
                        check_value: str, recommendation: str, source: str) -> int:
    with SessionFactory() as session:    
        securityrule = SecurityRule(code=code, title=title, category=category, severity=severity, vendor=vendor,
                                check_type=check_type, check_value=check_value, recommendation=recommendation, source=source)
        session.add(securityrule)
        session.commit()
        return securityrule.id

def list_securityrules(vendor: str | None = None) -> list[dict]:
    with SessionFactory() as session:
        statement = select(SecurityRule)
        if vendor is not None:
            statement = statement.where(SecurityRule.vendor == vendor)
        return [rule.to_dict() for rule in session.scalars(statement.order_by(SecurityRule.code)).all()]

def log_event(actor: str, action: str, object_type: str, object_id: int | None, result: str, message: str | None = None) -> None:
    with SessionFactory() as session:
        log = AuditLog(actor=actor, action=action, object_type=object_type, object_id=object_id, result=result, message=message)
        session.add(log)
        session.commit()

def list_audit_logs(limit: int = 50) -> list[dict]:
    with SessionFactory() as session:
        statement = select(AuditLog).order_by(AuditLog.occurred_at.desc()).limit(limit)
        return [log.to_dict() for log in session.scalars(statement).all()]