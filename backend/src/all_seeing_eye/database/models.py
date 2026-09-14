from sqlalchemy import String, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, DeclarativeBase, relationship
from datetime import datetime
from typing import List
from sqlalchemy.dialects.postgresql import INET
from all_seeing_eye.database import engine

class Base(DeclarativeBase):
    pass

class Scan(Base):
    __tablename__ = "scan"

    id: Mapped[int] = mapped_column(primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String())

    scan_devices: Mapped[List["ScanDevice"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    connections: Mapped[List["Connection"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

class Device(Base):
    __tablename__ = "device"

    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String())
    vendor: Mapped[str] = mapped_column(String())
    os_version: Mapped[str] = mapped_column(String())
    management_ip: Mapped[str] = mapped_column(INET)

    scan_devices: Mapped[List["ScanDevice"]] = relationship(back_populates="device")
    interfaces: Mapped[List["Interface"]] = relationship(back_populates="device", cascade="all, delete-orphan")
    configuration: Mapped["Configuration | None"] = relationship(back_populates="device", uselist=False)

class ScanDevice(Base):
    __tablename__ = "scandevice"

    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id"), primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("device.id"), primary_key=True)

    scan: Mapped["Scan"] = relationship(back_populates="scan_devices")
    device: Mapped["Device"] = relationship(back_populates="scan_devices")

class Interface(Base):
    __tablename__ = "interface"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("device.id"))
    name: Mapped[str] = mapped_column(String())

    source_connections: Mapped[List["Connection"]] = relationship(back_populates="source_interface", foreign_keys="Connection.source_interface_id")
    target_connections: Mapped[List["Connection"]] = relationship(back_populates="target_interface", foreign_keys="Connection.target_interface_id")
    device: Mapped["Device"] = relationship(back_populates="interfaces")

class Connection(Base):
    __tablename__ = "connection"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id"))
    source_interface_id: Mapped[int] = mapped_column(ForeignKey("interface.id"))
    target_interface_id: Mapped[int] = mapped_column(ForeignKey("interface.id"))

    source_interface: Mapped["Interface"] = relationship(back_populates="source_connections", foreign_keys=[source_interface_id])
    target_interface: Mapped["Interface"] = relationship(back_populates="target_connections", foreign_keys=[target_interface_id])
    scan: Mapped["Scan"] = relationship(back_populates="connections")

class Configuration(Base):
    __tablename__ = "configuration"

    device_id: Mapped[int] = mapped_column(ForeignKey("device.id"), primary_key=True)
    content: Mapped[str] = mapped_column(Text)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    device: Mapped["Device"] = relationship(back_populates="configuration", uselist=False)
    analyses: Mapped[List["Analysis"]] = relationship(back_populates="configuration", cascade="all, delete-orphan")

class Analysis(Base):
    __tablename__ = "analysis"

    id: Mapped[int] = mapped_column(primary_key=True)
    configuration_id: Mapped[int] = mapped_column(ForeignKey("configuration.device_id"))
    method: Mapped[str] = mapped_column(String())
    status: Mapped[str] = mapped_column(String())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    configuration: Mapped["Configuration"] = relationship(back_populates="analyses")
    report: Mapped["Report | None"] = relationship(back_populates="analysis", uselist=False)
    findings: Mapped[List["Findings"]] = relationship(back_populates="analysis", cascade="all, delete-orphan")

class Report(Base):
    __tablename__ = "report"

    analysis_id: Mapped[int] = mapped_column(ForeignKey("analysis.id"), primary_key=True)
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    analysis: Mapped["Analysis"] = relationship(back_populates="report", uselist=False)

class SecurityRule(Base):
    __tablename__ = "securityrule"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String())
    title: Mapped[str] = mapped_column(String())
    severity: Mapped[str] = mapped_column(String())
    check_type: Mapped[str] = mapped_column(String())
    check_value: Mapped[str] = mapped_column(String())
    recommendation: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String())

    findings: Mapped[List["Findings"]] = relationship(back_populates="securityrule")

class Findings(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analysis.id"))
    rule_id: Mapped[int] = mapped_column(ForeignKey("securityrule.id"))
    evidence: Mapped[str] = mapped_column(String())
    status: Mapped[str] = mapped_column(String())

    analysis: Mapped["Analysis"] = relationship(back_populates="findings")
    securityrule: Mapped["SecurityRule"] = relationship(back_populates="findings")

if __name__ == "__main__":
    Base.metadata.create_all(engine)