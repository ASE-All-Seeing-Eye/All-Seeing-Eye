from sqlalchemy import String, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, DeclarativeBase, relationship
from datetime import datetime
from typing import List
from sqlalchemy.dialects.postgresql import INET, ARRAY, JSONB
from sqlalchemy import Integer, func, UniqueConstraint

class Base(DeclarativeBase):
    def to_dict(self) -> dict:
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

class Job(Base):
    __tablename__ = "job"

    id: Mapped[int] = mapped_column(primary_key=True)
    target: Mapped[str] = mapped_column(String())
    status:  Mapped[str] = mapped_column(String())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)

    scans: Mapped[List["Scan"]] = relationship(back_populates="job", cascade="all, delete-orphan")
    collections: Mapped[List["Collection"]] = relationship(back_populates="job", cascade="all, delete-orphan")
    report: Mapped["Report | None"] = relationship(back_populates="job", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scan"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("job.id"))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String())

    job: Mapped["Job"] = relationship(back_populates="scans", foreign_keys=[job_id])
    scanhosts: Mapped[List["ScanHost"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

class ScanHost(Base):
    __tablename__ = "scanhost"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id"))
    device_id: Mapped[int | None] = mapped_column(ForeignKey("device.id"))
    ip_address: Mapped[str] = mapped_column(INET)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    open_tcp_ports: Mapped[list[int] | None] = mapped_column(ARRAY(Integer))
    open_udp_ports: Mapped[list[int] | None] = mapped_column(ARRAY(Integer))

    scan: Mapped["Scan"] = relationship(back_populates="scanhosts", foreign_keys=[scan_id])
    device: Mapped["Device | None"] = relationship(back_populates="scanhosts", foreign_keys=[device_id])

class Device(Base):
    __tablename__ = "device"

    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str | None] = mapped_column(String())
    vendor: Mapped[str | None] = mapped_column(String())
    model: Mapped[str | None] = mapped_column(String())
    os_type: Mapped[str | None] = mapped_column(String())
    os_version: Mapped[str | None] = mapped_column(String())
    management_ip: Mapped[str] = mapped_column(INET, unique=True)

    scanhosts: Mapped[List["ScanHost"]] = relationship(back_populates="device")
    interfaces: Mapped[List["Interface"]] = relationship(back_populates="device", cascade="all, delete-orphan")
    collections: Mapped[List["Collection"]] = relationship(back_populates="device", cascade="all, delete-orphan")

class Interface(Base):
    __tablename__ = "interface"
    __table_args__ = (UniqueConstraint("device_id", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("device.id"))
    name: Mapped[str] = mapped_column(String())
    description: Mapped[str | None] = mapped_column(Text)
    ip_address: Mapped[str | None] = mapped_column(INET)
    mac_address: Mapped[str | None] = mapped_column(String())
    status: Mapped[str | None] = mapped_column(String())
    mode: Mapped[str | None] = mapped_column(String())
    vlan: Mapped[int | None]= mapped_column(Integer())

    source_connections: Mapped[List["Connection"]] = relationship(back_populates="source_interface", foreign_keys="Connection.source_interface_id")
    target_connections: Mapped[List["Connection"]] = relationship(back_populates="target_interface", foreign_keys="Connection.target_interface_id")
    device: Mapped["Device"] = relationship(back_populates="interfaces")

class Connection(Base):
    __tablename__ = "connection"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_interface_id: Mapped[int] = mapped_column(ForeignKey("interface.id"))
    target_interface_id: Mapped[int | None] = mapped_column(ForeignKey("interface.id"))
    remote_hostname: Mapped[str | None] = mapped_column(String())
    remote_interface: Mapped[str | None] = mapped_column(String())
    method: Mapped[str] = mapped_column(String())

    source_interface: Mapped["Interface"] = relationship(back_populates="source_connections", foreign_keys=[source_interface_id])
    target_interface: Mapped["Interface | None"] = relationship(back_populates="target_connections", foreign_keys=[target_interface_id])

class Collection(Base):
    __tablename__ = "collection"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("device.id"))
    job_id: Mapped[int] = mapped_column(ForeignKey("job.id"))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    status: Mapped[str] = mapped_column(String())
    error_message: Mapped[str | None] = mapped_column(Text)

    device: Mapped["Device"] = relationship(back_populates="collections", foreign_keys=[device_id])
    job: Mapped["Job"] = relationship(back_populates="collections", foreign_keys=[job_id])
    configuration: Mapped["Configuration | None"] = relationship(back_populates="collection", cascade="all, delete-orphan")
    commands: Mapped[List["Command"]] = relationship(back_populates="collection", cascade="all, delete-orphan")
    analyses: Mapped[List["Analysis"]] = relationship(back_populates="collection", cascade="all, delete-orphan")

class Configuration(Base):
    __tablename__ = "configuration"

    id: Mapped[int] = mapped_column(primary_key=True)
    collection_id: Mapped[int] = mapped_column(ForeignKey("collection.id"), unique=True)
    content: Mapped[str] = mapped_column(Text)
    parsed: Mapped[dict | None] = mapped_column(JSONB())
    parse_status: Mapped[str] = mapped_column(String())
    error_message: Mapped[str | None] = mapped_column(Text)

    collection: Mapped["Collection"] = relationship(back_populates="configuration", foreign_keys=[collection_id])

class Command(Base):
    __tablename__ = "command"
    __table_args__ = (UniqueConstraint("collection_id", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    collection_id: Mapped[int] = mapped_column(ForeignKey("collection.id"))
    name: Mapped[str] = mapped_column(String())
    output: Mapped[str | None] = mapped_column(Text)
    parsed: Mapped[dict | None] = mapped_column(JSONB())
    parse_status: Mapped[str] = mapped_column(String())
    error_message: Mapped[str | None] = mapped_column(Text)

    collection: Mapped["Collection"] = relationship(back_populates="commands", foreign_keys=[collection_id])

class Analysis(Base):
    __tablename__ = "analysis"

    id: Mapped[int] = mapped_column(primary_key=True)
    collection_id: Mapped[int] = mapped_column(ForeignKey("collection.id"))
    method: Mapped[str] = mapped_column(String())
    ai_model: Mapped[str | None] = mapped_column(String())
    status: Mapped[str] = mapped_column(String())
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    collection: Mapped["Collection"] = relationship(back_populates="analyses", foreign_keys=[collection_id])
    findings: Mapped[List["Finding"]] = relationship(back_populates="analysis", cascade="all, delete-orphan")

class Report(Base):
    __tablename__ = "report"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("job.id"), unique=True)
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    job: Mapped["Job"] = relationship(back_populates="report", foreign_keys=[job_id])

class SecurityRule(Base):
    __tablename__ = "securityrule"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(), unique=True)
    title: Mapped[str] = mapped_column(String())
    category: Mapped[str] = mapped_column(String())
    severity: Mapped[str] = mapped_column(String())
    vendor: Mapped[str] = mapped_column(String())
    check_type: Mapped[str] = mapped_column(String())
    check_value: Mapped[str] = mapped_column(String())
    recommendation: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String())

    findings: Mapped[List["Finding"]] = relationship(back_populates="rule")

class Finding(Base):
    __tablename__ = "finding"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analysis.id"))
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("securityrule.id"))
    detected_by: Mapped[str] = mapped_column(String())
    title: Mapped[str] = mapped_column(String())
    category: Mapped[str] = mapped_column(String())
    severity: Mapped[str] = mapped_column(String())
    description: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text)

    analysis: Mapped["Analysis"] = relationship(back_populates="findings", foreign_keys=[analysis_id])
    rule: Mapped["SecurityRule | None"] = relationship(back_populates="findings", foreign_keys=[rule_id])

class AuditLog(Base):
    __tablename__ = "auditlog"

    id: Mapped[int] = mapped_column(primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    actor: Mapped[str] = mapped_column(String())
    action: Mapped[str] = mapped_column(String())
    object_type: Mapped[str] = mapped_column(String())
    object_id: Mapped[int | None] = mapped_column(Integer())
    result: Mapped[str] = mapped_column(String())
    message: Mapped[str | None] = mapped_column(Text)

if __name__ == "__main__":
    from all_seeing_eye.database.session import engine
    Base.metadata.create_all(engine)
