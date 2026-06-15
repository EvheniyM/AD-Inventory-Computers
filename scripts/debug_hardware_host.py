import json
import sys

import winrm

from app.config import get_settings
from app.hardware_collector import (
    _collect_current_pnp_monitors,
    _collect_current_pnp_monitors_wsman,
    _collect_graphics_registry_monitors,
    _display_ids_from_graphics_registry,
    _endpoint,
    _reg_query_edid,
    _wmic,
    _wsman_wmi_query,
    collect_hardware_for_computer,
)


def monitor_sources(settings, target: str) -> dict:
    session = winrm.Session(
        _endpoint(settings, target),
        auth=(settings.hardware_winrm_user, settings.hardware_winrm_password),
        transport=settings.hardware_winrm_transport,
        server_cert_validation=settings.hardware_winrm_server_cert_validation,
        operation_timeout_sec=settings.hardware_winrm_operation_timeout_seconds,
        read_timeout_sec=settings.hardware_winrm_read_timeout_seconds,
    )
    wsman_monitor_rows, wsman_monitor_error = _wsman_wmi_query(settings, target, "root/wmi", "WmiMonitorID")
    monitor_rows, monitor_error = _wmic(
        session,
        [
            "/namespace:\\\\root\\wmi",
            "path",
            "WmiMonitorID",
            "get",
            "Active,ManufacturerName,SerialNumberID,UserFriendlyName",
            "/value",
        ],
    )
    pnp_rows, pnp_error = _wmic(
        session,
        [
            "path",
            "Win32_PnPEntity",
            "get",
            "ConfigManagerErrorCode,Manufacturer,Name,PNPDeviceID,Service",
            "/value",
        ],
    )
    display_rows = []
    for row in pnp_rows:
        pnp_device_id = row.get("PNPDeviceID") or ""
        if pnp_device_id.upper().startswith("DISPLAY\\"):
            display_rows.append(
                {
                    "config_error": row.get("ConfigManagerErrorCode"),
                    "manufacturer": row.get("Manufacturer"),
                    "name": row.get("Name"),
                    "pnp_device_id": pnp_device_id,
                    "service": row.get("Service"),
                    "edid_monitor": _reg_query_edid(session, pnp_device_id),
                }
            )
    return {
        "wsman_monitor_error": wsman_monitor_error,
        "wsman_monitor_rows": wsman_monitor_rows,
        "wmi_monitor_error": monitor_error,
        "wmi_monitor_rows": monitor_rows,
        "pnp_error": pnp_error,
        "pnp_display_rows": display_rows,
        "wsman_pnp_monitor_result": _collect_current_pnp_monitors_wsman(settings, target, session),
        "graphics_display_ids": _display_ids_from_graphics_registry(session),
        "pnp_monitor_result": _collect_current_pnp_monitors(session),
        "graphics_monitor_result": _collect_graphics_registry_monitors(session),
        "graphics_monitor_result_limited": _collect_graphics_registry_monitors(session, settings.hardware_max_monitors),
    }


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: python -m scripts.debug_hardware_host HOSTNAME_OR_IP [--monitor-sources]")
        raise SystemExit(2)
    target = sys.argv[1].strip()
    include_monitor_sources = "--monitor-sources" in sys.argv[2:]
    settings = get_settings()
    hostname, resolved_target, payload, error = collect_hardware_for_computer(
        settings,
        {
            "name": target,
            "cn": target,
            "dNSHostName": target,
            "ip_address": target,
            "source_type": "physical",
        },
    )
    print(
        json.dumps(
            {
                "hostname": hostname,
                "target": resolved_target,
                "mode": settings.hardware_collection_mode,
                "error": error,
                "payload": payload,
                "monitor_sources": monitor_sources(settings, resolved_target or target) if include_monitor_sources else None,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
