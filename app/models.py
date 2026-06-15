import datetime as dt

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Machine(Base):
    __tablename__ = "machines"
    __table_args__ = (UniqueConstraint("normalized_hostname", name="uq_machines_normalized_hostname"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    normalized_hostname: Mapped[str] = mapped_column(String(255), index=True)
    source_type: Mapped[str] = mapped_column(String(32), default="physical")
    source_ou: Mapped[str | None] = mapped_column(Text)
    computer_dn: Mapped[str | None] = mapped_column(Text)
    object_guid: Mapped[str | None] = mapped_column(String(128), index=True)
    dns_hostname: Mapped[str | None] = mapped_column(String(255))

    ad_user_dn: Mapped[str | None] = mapped_column(Text)
    ad_user_sam: Mapped[str | None] = mapped_column(String(255))
    manual_user_key: Mapped[str | None] = mapped_column(String(255))
    full_name: Mapped[str | None] = mapped_column(String(255))
    position_title: Mapped[str | None] = mapped_column(String(255))
    department: Mapped[str | None] = mapped_column(String(255))
    company: Mapped[str | None] = mapped_column(String(255))

    works_on: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(String(255))
    mac_address: Mapped[str | None] = mapped_column(String(255))
    socket: Mapped[str | None] = mapped_column(String(255))
    inventory_pc: Mapped[str | None] = mapped_column(String(255))
    switch_port: Mapped[str | None] = mapped_column(String(255))
    location: Mapped[str | None] = mapped_column(String(255))
    oschad_access: Mapped[str | None] = mapped_column(String(64))
    note: Mapped[str | None] = mapped_column(Text)
    hardware_cpu: Mapped[str | None] = mapped_column(String(255))
    hardware_ram: Mapped[str | None] = mapped_column(Text)
    hardware_disks: Mapped[str | None] = mapped_column(Text)
    hardware_gpu: Mapped[str | None] = mapped_column(String(255))
    hardware_motherboard: Mapped[str | None] = mapped_column(String(255))
    hardware_monitors: Mapped[str | None] = mapped_column(Text)
    hardware_network: Mapped[str | None] = mapped_column(Text)
    hardware_updated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    match_status: Mapped[str] = mapped_column(String(32), default="not_synced")
    match_score: Mapped[int] = mapped_column(Integer, default=0)
    match_note: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_synced_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class SyncEvent(Base):
    __tablename__ = "sync_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), default="running")
    seen_computers: Mapped[int] = mapped_column(Integer, default=0)
    created_rows: Mapped[int] = mapped_column(Integer, default=0)
    updated_rows: Mapped[int] = mapped_column(Integer, default=0)
    deleted_rows: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[str | None] = mapped_column(Text)
