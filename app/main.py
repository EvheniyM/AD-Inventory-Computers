from __future__ import annotations

import io
import secrets
import datetime as dt
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from app.auth import require_auth
from app.db import get_db, init_db
from app.excel_service import import_workbook, maybe_write_export, workbook_to_bytes
from app.config import get_settings
from app.ip_utils import ip_in_configured_ranges
from app.logging_config import configure_logging
from app.matcher import normalize_hostname
from app.models import Machine, SyncEvent
from app.sync_service import run_sync


settings = get_settings()
configure_logging(settings.app_timezone)

app = FastAPI(title="BARS T18 Inventory")
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")


class HardwareReport(BaseModel):
    hostname: str
    cpu: str | None = None
    ram: str | None = None
    disks: str | None = None
    gpu: str | None = None
    motherboard: str | None = None
    monitors: str | None = None
    network: str | None = None


def format_local_datetime(value: dt.datetime | None) -> str:
    if value is None:
        return ""
    try:
        timezone = ZoneInfo(settings.app_timezone)
    except ZoneInfoNotFoundError:
        timezone = ZoneInfo("UTC")
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(timezone).strftime("%Y-%m-%d %H:%M:%S")


templates.env.filters["local_dt"] = format_local_datetime


def has_wifi_ip(ip_address: str | None) -> bool:
    return ip_in_configured_ranges(ip_address, get_settings().wifi_networks)


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/hardware/report")
def receive_hardware_report(
    report: HardwareReport,
    x_inventory_token: str = Header("", alias="X-Inventory-Token"),
    db: Session = Depends(get_db),
):
    settings = get_settings()
    if not settings.hardware_report_token:
        raise HTTPException(status_code=404, detail="hardware reporting is disabled")
    if not secrets.compare_digest(x_inventory_token, settings.hardware_report_token):
        raise HTTPException(status_code=403, detail="invalid hardware report token")

    normalized = normalize_hostname(report.hostname)
    if not normalized:
        raise HTTPException(status_code=400, detail="hostname is empty")

    machine = db.scalar(select(Machine).where(Machine.normalized_hostname == normalized))
    if machine is None:
        machine = Machine(
            hostname=report.hostname.strip().upper(),
            normalized_hostname=normalized,
            source_type="virtual" if normalized.startswith("vm-") else "physical",
            match_status="hardware_report",
            match_score=0,
            match_note="created from hardware report",
        )
        db.add(machine)

    machine.hardware_cpu = (report.cpu or "").strip() or None
    machine.hardware_ram = (report.ram or "").strip() or None
    machine.hardware_disks = (report.disks or "").strip() or None
    machine.hardware_gpu = (report.gpu or "").strip() or None
    machine.hardware_motherboard = (report.motherboard or "").strip() or None
    machine.hardware_monitors = (report.monitors or "").strip() or None
    machine.hardware_network = (report.network or "").strip() or None
    machine.hardware_updated_at = dt.datetime.now(dt.timezone.utc)
    db.commit()
    return {"status": "ok", "hostname": machine.hostname}


@app.get("/")
def index(
    request: Request,
    q: str = "",
    source_type: str = "",
    match_status: str = "",
    msg: str = "",
    db: Session = Depends(get_db),
    _: str = Depends(require_auth),
):
    stmt = select(Machine)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(
                Machine.hostname.ilike(like),
                Machine.full_name.ilike(like),
                Machine.position_title.ilike(like),
                Machine.ip_address.ilike(like),
                Machine.inventory_pc.ilike(like),
                Machine.manual_user_key.ilike(like),
            )
        )
    if source_type:
        stmt = stmt.where(Machine.source_type == source_type)
    if match_status:
        stmt = stmt.where(Machine.match_status == match_status)
    machines = list(
        db.scalars(
            stmt.order_by(
                case(
                    (Machine.source_type.in_(("server", "switch", "wifi", "network")), 1),
                    (Machine.source_type == "printer", 2),
                    else_=0,
                ),
                Machine.company,
                Machine.full_name,
                Machine.hostname,
            )
        ).all()
    )
    for machine in machines:
        if machine.source_type in {"physical", "virtual"} and has_wifi_ip(machine.ip_address):
            machine.works_on = "Ноутбук"
    last_event = db.scalar(select(SyncEvent).order_by(SyncEvent.started_at.desc()).limit(1))
    total = db.scalar(select(func.count(Machine.id))) or 0
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "machines": machines,
            "q": q,
            "source_type": source_type,
            "match_status": match_status,
            "msg": msg,
            "last_event": last_event,
            "total": total,
        },
    )


@app.get("/machines/{machine_id}")
def edit_machine(
    machine_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(require_auth),
):
    machine = db.get(Machine, machine_id)
    if machine is None:
        return RedirectResponse("/?msg=record_not_found", status_code=303)
    return templates.TemplateResponse("edit.html", {"request": request, "machine": machine})


@app.get("/machines/{machine_id}/view")
def view_machine(
    machine_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(require_auth),
):
    machine = db.get(Machine, machine_id)
    if machine is None:
        return RedirectResponse("/?msg=record_not_found", status_code=303)
    return templates.TemplateResponse("view.html", {"request": request, "machine": machine})


@app.post("/machines/{machine_id}")
def update_machine(
    machine_id: int,
    works_on: str = Form(""),
    ip_address: str = Form(""),
    mac_address: str = Form(""),
    socket: str = Form(""),
    inventory_pc: str = Form(""),
    switch_port: str = Form(""),
    location: str = Form(""),
    oschad_access: str = Form(""),
    note: str = Form(""),
    manual_user_key: str | None = Form(None),
    hardware_cpu: str = Form(""),
    hardware_ram: str = Form(""),
    hardware_disks: str = Form(""),
    hardware_gpu: str = Form(""),
    hardware_motherboard: str = Form(""),
    hardware_monitors: str = Form(""),
    hardware_network: str = Form(""),
    db: Session = Depends(get_db),
    _: str = Depends(require_auth),
):
    machine = db.get(Machine, machine_id)
    if machine is None:
        return RedirectResponse("/?msg=record_not_found", status_code=303)

    machine.works_on = works_on.strip() or None
    machine.ip_address = ip_address.strip() or None
    if machine.source_type in {"physical", "virtual"} and has_wifi_ip(machine.ip_address):
        machine.works_on = "Ноутбук"
    machine.mac_address = mac_address.strip() or None
    machine.socket = socket.strip() or None
    machine.inventory_pc = inventory_pc.strip() or None
    machine.switch_port = switch_port.strip() or None
    machine.location = location.strip() or None
    machine.oschad_access = oschad_access.strip() or None
    machine.note = note.strip() or None
    if manual_user_key is not None:
        machine.manual_user_key = manual_user_key.strip() or None
    machine.hardware_cpu = hardware_cpu.strip() or None
    machine.hardware_ram = hardware_ram.strip() or None
    machine.hardware_disks = hardware_disks.strip() or None
    machine.hardware_gpu = hardware_gpu.strip() or None
    machine.hardware_motherboard = hardware_motherboard.strip() or None
    machine.hardware_monitors = hardware_monitors.strip() or None
    machine.hardware_network = hardware_network.strip() or None
    db.commit()
    maybe_write_export(db)
    return RedirectResponse(f"/?q={machine.hostname}&msg=saved", status_code=303)


@app.post("/sync/run")
def run_sync_now(db: Session = Depends(get_db), _: str = Depends(require_auth)):
    event = run_sync(db, include_discovery=False)
    return RedirectResponse(f"/?msg=sync_{event.status}", status_code=303)


@app.get("/export.xlsx")
def export_xlsx(db: Session = Depends(get_db), _: str = Depends(require_auth)):
    content = workbook_to_bytes(db)
    return Response(
        content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="inventory.xlsx"'},
    )


@app.get("/import")
def import_page(request: Request, db: Session = Depends(get_db), _: str = Depends(require_auth)):
    return templates.TemplateResponse("import.html", {"request": request, "msg": "", "imported": None})


@app.post("/import")
async def import_upload(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    _: str = Depends(require_auth),
):
    content = await file.read()
    imported = import_workbook(io.BytesIO(content), db)
    return templates.TemplateResponse("import.html", {"request": request, "msg": "imported", "imported": imported})
