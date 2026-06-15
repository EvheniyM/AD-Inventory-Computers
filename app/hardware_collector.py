import base64
import datetime as dt
import html
import json
import logging
import os
import re
import socket
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from xml.etree import ElementTree as ET

import requests
import winrm
from requests_ntlm import HttpNtlmAuth
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.ad_client import ActiveDirectoryClient
from app.config import Settings, get_settings
from app.db import SessionLocal, init_db
from app.logging_config import configure_logging
from app.matcher import normalize_hostname
from app.models import Machine


logger = logging.getLogger(__name__)

BASE_HARDWARE_SCRIPT = r"""
$ErrorActionPreference="Stop"
$ProgressPreference="SilentlyContinue"
function J($v){(($v|?{$_ -and "$_".Trim()}|%{"$_".Trim()})-join "; ")}
function G($b){if(!$b){""}else{("{0:N1} GB"-f($b/1GB))}}
$cpu=J @(Get-CimInstance Win32_Processor|% Name)
$d=J @(Get-CimInstance Win32_DiskDrive|%{J @($_.Model,(G $_.Size))})
$gpu=J @(Get-CimInstance Win32_VideoController|% Name)
$b=Get-CimInstance Win32_BaseBoard|select -First 1
[pscustomobject]@{
 hostname=$env:COMPUTERNAME
 cpu=$cpu
 disks=$d
 gpu=$gpu
 motherboard=J @($b.Manufacturer,$b.Product,$b.SerialNumber)
}|ConvertTo-Json -Compress
"""

MEMORY_HARDWARE_SCRIPT = r"""
$ErrorActionPreference="Stop"
$ProgressPreference="SilentlyContinue"
try {
function J($v){(($v|?{$_ -and "$_".Trim()}|%{"$_".Trim()})-join "; ")}
function G($b){if(!$b){""}else{("{0:N1} GB"-f($b/1GB))}}
$c=Get-CimInstance Win32_ComputerSystem
$mods=@(Get-CimInstance Win32_PhysicalMemory -ea SilentlyContinue|?{$_.Capacity})
$slots=0;@(Get-CimInstance Win32_PhysicalMemoryArray -ea SilentlyContinue)|%{if($_.MemoryDevices){$slots+=[int]$_.MemoryDevices}}
$used=@($mods).Count
$sum=if($slots -gt 0){"slots $used/$slots used, $([Math]::Max(0,$slots-$used)) free"}elseif($used -gt 0){"modules $used"}else{""}
$vals=@($mods|sort DeviceLocator,BankLabel|%{$sp=if($_.ConfiguredClockSpeed){$_.ConfiguredClockSpeed}elseif($_.Speed){$_.Speed}else{$null};J @((J @($_.DeviceLocator,$_.BankLabel)),(G $_.Capacity),$(if($sp){"$sp MHz"}else{""}),(J @($_.Manufacturer,$_.PartNumber)))})
[pscustomobject]@{ram=J @((G $c.TotalPhysicalMemory),$sum,(J @($vals)))}|ConvertTo-Json -Compress
} catch {
 [pscustomobject]@{ram=""}|ConvertTo-Json -Compress
}
"""

MONITOR_HARDWARE_SCRIPT = r"""
$ErrorActionPreference="SilentlyContinue"
$ProgressPreference="SilentlyContinue"
try {
function J($v){(($v|?{$_ -and "$_".Trim()}|%{"$_".Trim()})-join "; ")}
function A($b){if(!$b){""}else{(($b|?{$_ -and $_ -ne 0 -and $_ -ne 10 -and $_ -ne 13}|%{[char][int]$_})-join "").Trim()}}
function M($c){if(!$c){""}else{switch($c.ToUpper()){"ACI"{"ASUS"}"AOC"{"AOC"}"BNQ"{"BenQ"}"DEL"{"Dell"}"GSM"{"LG"}"HWP"{"HP"}"LEN"{"Lenovo"}"PHL"{"Philips"}"SAM"{"Samsung"}"SEC"{"Samsung"}"SNY"{"Sony"}default{$c}}}}
$rows=@(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ea SilentlyContinue)
$active=@($rows|?{$_.Active -eq $true})
if(@($active).Count -eq 0 -and @($rows).Count -gt 0){$active=$rows}
$v=@($active|%{
 $row=J @((M (A $_.ManufacturerName)),(A $_.UserFriendlyName),(A $_.SerialNumberID))
 if($row){$row}
})
$v=@($v|sort -Unique)
[pscustomobject]@{monitors=J @($v)}|ConvertTo-Json -Compress
} catch {
 [pscustomobject]@{monitors=""}|ConvertTo-Json -Compress
}
"""

NETWORK_HARDWARE_SCRIPT = r"""
$ErrorActionPreference="Stop"
$ProgressPreference="SilentlyContinue"
try {
function J($v){(($v|?{$_ -and "$_".Trim()}|%{"$_".Trim()})-join "; ")}
function S($b){if(!$b){""}elseif($b -ge 1000000000){$g=[double]$b/1000000000;if([Math]::Abs($g-[Math]::Round($g))-lt .05){("{0:N0} Gb/s"-f$g)}else{("{0:N1} Gb/s"-f$g)}}elseif($b -ge 1000000){("{0:N0} Mb/s"-f([double]$b/1000000))}else{("{0:N0} b/s"-f[double]$b)}}
function C($s){if($null -eq $s){""}else{switch([int]$s){0{"Disconnected"}1{"Connecting"}2{"Connected"}3{"Disconnecting"}4{"Hardware not present"}5{"Disabled"}6{"Hardware malfunction"}7{"Media disconnected"}8{"Authenticating"}9{"Authentication succeeded"}10{"Authentication failed"}11{"Invalid address"}12{"Credentials required"}default{"Status $s"}}}}
$a=@(Get-CimInstance Win32_NetworkAdapter -ea SilentlyContinue|?{$_.PhysicalAdapter -eq $true -and $_.MACAddress -and $_.Name -notmatch "WAN Miniport|Kernel Debug|Bluetooth Device|Microsoft ISATAP|Teredo|Loopback"})
$vals=@($a|sort NetConnectionID,Name|%{J @((J @($_.NetConnectionID,$_.Name)),(C $_.NetConnectionStatus),(S $_.Speed),$_.MACAddress)})
$p=@($a).Count;$u=@($a|?{$_.NetConnectionStatus -eq 2}).Count;$sum=if($p -gt 0){"ports $u/$p connected"}else{""}
[pscustomobject]@{network=J @($sum,(J @($vals)))}|ConvertTo-Json -Compress
} catch {
 [pscustomobject]@{network=""}|ConvertTo-Json -Compress
}
"""

def enabled_hardware_scripts(settings: Settings) -> tuple[tuple[str, str, bool], ...]:
    scripts: list[tuple[str, str, bool]] = [("base", BASE_HARDWARE_SCRIPT, True)]
    if settings.hardware_collect_memory_details:
        scripts.append(("memory", MEMORY_HARDWARE_SCRIPT, False))
    if settings.hardware_collect_monitors:
        scripts.append(("monitors", MONITOR_HARDWARE_SCRIPT, False))
    if settings.hardware_collect_network_adapters:
        scripts.append(("network", NETWORK_HARDWARE_SCRIPT, False))
    return tuple(scripts)


def configure_timezone(timezone_name: str) -> None:
    os.environ["TZ"] = timezone_name
    if hasattr(time, "tzset"):
        time.tzset()


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _short_hostname(value: Any) -> str | None:
    cleaned = _clean(value)
    if not cleaned:
        return None
    return cleaned.split(".", 1)[0].upper()


def _computer_hostname(computer: dict[str, Any]) -> str | None:
    return _short_hostname(computer.get("dNSHostName")) or _short_hostname(computer.get("name") or computer.get("cn"))


def _computer_target(computer: dict[str, Any]) -> str | None:
    return _clean(computer.get("dNSHostName")) or _clean(computer.get("ip_address")) or _computer_hostname(computer)


def _endpoint(settings: Settings, target: str) -> str:
    return f"{settings.hardware_winrm_scheme}://{target}:{settings.hardware_winrm_port}/wsman"


def _xml_escape(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def _xml_local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _wsman_wmi_resource(namespace: str, class_name: str) -> str:
    cleaned_namespace = namespace.strip("\\/").replace("\\", "/")
    return f"http://schemas.microsoft.com/wbem/wsman/1/wmi/{cleaned_namespace}/{class_name}"


def _wsman_envelope(
    endpoint: str,
    action: str,
    resource_uri: str,
    body: str,
    operation_timeout_seconds: int,
) -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:e="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
  <s:Header>
    <a:To>{_xml_escape(endpoint)}</a:To>
    <a:ReplyTo>
      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <a:Action s:mustUnderstand="true">{_xml_escape(action)}</a:Action>
    <a:MessageID>uuid:{uuid.uuid4()}</a:MessageID>
    <w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>
    <w:OperationTimeout>PT{max(5, int(operation_timeout_seconds))}S</w:OperationTimeout>
    <w:ResourceURI s:mustUnderstand="true">{_xml_escape(resource_uri)}</w:ResourceURI>
  </s:Header>
  <s:Body>{body}</s:Body>
</s:Envelope>"""


def _wsman_post(settings: Settings, target: str, action: str, resource_uri: str, body: str) -> tuple[ET.Element | None, str | None]:
    endpoint = _endpoint(settings, target)
    headers = {"Content-Type": "application/soap+xml;charset=UTF-8"}
    verify = settings.hardware_winrm_server_cert_validation == "validate"
    try:
        response = requests.post(
            endpoint,
            data=_wsman_envelope(
                endpoint,
                action,
                resource_uri,
                body,
                settings.hardware_winrm_operation_timeout_seconds,
            ).encode("utf-8"),
            headers=headers,
            auth=HttpNtlmAuth(settings.hardware_winrm_user, settings.hardware_winrm_password),
            timeout=settings.hardware_winrm_read_timeout_seconds,
            verify=verify,
        )
    except requests.RequestException as exc:
        return None, str(exc)
    if response.status_code >= 400:
        return None, f"WSMan HTTP {response.status_code}: {response.text[:400]}"
    try:
        root = ET.fromstring(response.content)
    except ET.ParseError as exc:
        return None, f"invalid WSMan XML: {exc}"
    for fault in root.iter():
        if _xml_local_name(fault.tag) == "Fault":
            reason = ""
            for item in fault.iter():
                if _xml_local_name(item.tag) in {"Text", "Reason"} and item.text:
                    reason = item.text.strip()
                    break
            return None, reason or "WSMan fault"
    return root, None


def _wsman_element_value(element: ET.Element) -> str:
    children = list(element)
    if not children:
        return (element.text or "").strip()
    values = [(child.text or "").strip() for child in children if (child.text or "").strip()]
    return "{" + ",".join(values) + "}" if values else ""


def _wsman_extract_items(root: ET.Element, class_name: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for item in root.iter():
        if _xml_local_name(item.tag) != class_name:
            continue
        row: dict[str, str] = {}
        for child in list(item):
            key = _xml_local_name(child.tag)
            row[key] = _wsman_element_value(child)
        if row:
            rows.append(row)
    return rows


def _wsman_enumeration_context(root: ET.Element) -> str | None:
    for item in root.iter():
        if _xml_local_name(item.tag) == "EnumerationContext" and item.text:
            return item.text.strip()
    return None


def _wsman_wmi_query(
    settings: Settings,
    target: str,
    namespace: str,
    class_name: str,
) -> tuple[list[dict[str, str]], str | None]:
    resource_uri = _wsman_wmi_resource(namespace, class_name)
    enumerate_action = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
    pull_action = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"
    root, error = _wsman_post(
        settings,
        target,
        enumerate_action,
        resource_uri,
        "<e:Enumerate><w:OptimizeEnumeration/><w:MaxElements>512</w:MaxElements></e:Enumerate>",
    )
    if error or root is None:
        return [], error
    rows = _wsman_extract_items(root, class_name)
    context = _wsman_enumeration_context(root)
    while context:
        root, error = _wsman_post(
            settings,
            target,
            pull_action,
            resource_uri,
            (
                "<e:Pull>"
                f"<e:EnumerationContext>{_xml_escape(context)}</e:EnumerationContext>"
                "<e:MaxElements>512</e:MaxElements>"
                "</e:Pull>"
            ),
        )
        if error or root is None:
            return rows, error
        rows.extend(_wsman_extract_items(root, class_name))
        new_context = _wsman_enumeration_context(root)
        if not new_context or new_context == context:
            break
        context = new_context
    return rows, None


def _tcp_port_reachable(hostname: str, port: int, timeout_seconds: float) -> bool:
    try:
        with socket.create_connection((hostname, port), timeout=timeout_seconds):
            return True
    except OSError:
        return False


def _clean_winrm_error(value: bytes) -> str:
    text = _decode_remote_output(value).strip()
    if text.startswith("#< CLIXML"):
        text = text.replace("#< CLIXML", "", 1)
        text = re.sub(r"<[^>]+>", " ", text)
        text = html.unescape(text)
        text = text.replace("_x000D__x000A_", " ")
        text = re.sub(r"\s+", " ", text).strip()
    return text


def _decode_remote_output(value: bytes) -> str:
    if not value:
        return ""
    if b"\x00" in value[:120]:
        try:
            return value.decode("utf-16-le", errors="replace")
        except UnicodeDecodeError:
            pass
    for encoding in ("utf-8-sig", "cp866", "cp1251"):
        try:
            return value.decode(encoding)
        except UnicodeDecodeError:
            continue
    return value.decode("utf-8", errors="replace")


def _run_remote_command(session: winrm.Session, command: str, args: list[str]) -> tuple[str, str | None]:
    result = session.run_cmd(command, args)
    if result.status_code != 0:
        error = _clean_winrm_error(result.std_err or b"")
        return "", error or f"{command} returned {result.status_code}"
    return _decode_remote_output(result.std_out or b""), None


def _parse_wmic_value_blocks(output: str) -> list[dict[str, str]]:
    blocks: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in current:
            blocks.append(current)
            current = {}
        current[key] = value.strip()
    if current:
        blocks.append(current)
    return blocks


def _wmic(session: winrm.Session, args: list[str]) -> tuple[list[dict[str, str]], str | None]:
    output, error = _run_remote_command(session, "wmic", args)
    if error:
        return [], error
    return _parse_wmic_value_blocks(output), None


def _wmic_join(values: list[Any]) -> str:
    return "; ".join(str(value).strip() for value in values if str(value or "").strip())


def _bytes_to_gb(value: Any) -> str:
    try:
        size = int(str(value or "0").strip())
    except ValueError:
        return ""
    if size <= 0:
        return ""
    return f"{size / 1024 / 1024 / 1024:.1f} GB".replace(".", ",")


def _wmic_speed(value: Any) -> str:
    try:
        speed = int(str(value or "0").strip())
    except ValueError:
        return ""
    if speed >= 1_000_000_000:
        gbps = speed / 1_000_000_000
        return f"{gbps:.0f} Gb/s" if abs(gbps - round(gbps)) < 0.05 else f"{gbps:.1f} Gb/s"
    if speed >= 1_000_000:
        return f"{speed / 1_000_000:.0f} Mb/s"
    return f"{speed} b/s" if speed else ""


def _wmic_adapter_status(value: Any) -> str:
    statuses = {
        "0": "Disconnected",
        "1": "Connecting",
        "2": "Connected",
        "3": "Disconnecting",
        "4": "Hardware not present",
        "5": "Disabled",
        "6": "Hardware malfunction",
        "7": "Media disconnected",
        "8": "Authenticating",
        "9": "Authentication succeeded",
        "10": "Authentication failed",
        "11": "Invalid address",
        "12": "Credentials required",
    }
    raw = str(value or "").strip()
    return statuses.get(raw, f"Status {raw}" if raw else "")


def _decode_wmi_char_array(value: Any) -> str:
    chars: list[str] = []
    for raw in re.findall(r"\d+", str(value or "")):
        try:
            item = int(raw)
        except ValueError:
            continue
        if item in {0, 10, 13}:
            continue
        if 0 < item <= 0x10FFFF:
            chars.append(chr(item))
    return "".join(chars).strip()


def _monitor_vendor(value: str) -> str:
    vendors = {
        "ACI": "ASUS",
        "AOC": "AOC",
        "BNQ": "BenQ",
        "DEL": "Dell",
        "GSM": "LG",
        "HWP": "HP",
        "LEN": "Lenovo",
        "PHL": "Philips",
        "SAM": "Samsung",
        "SEC": "Samsung",
        "SNY": "Sony",
    }
    return vendors.get(value.upper(), value)


def _decode_edid_vendor(edid: bytes) -> str:
    if len(edid) < 10:
        return ""
    value = (edid[8] << 8) | edid[9]
    chars = [
        chr(64 + ((value >> 10) & 31)),
        chr(64 + ((value >> 5) & 31)),
        chr(64 + (value & 31)),
    ]
    return _monitor_vendor("".join(chars).strip())


def _decode_edid_text(chunk: bytes) -> str:
    return "".join(chr(item) for item in chunk if item not in {0, 10, 13}).strip()


def _decode_edid_monitor(edid_hex: str) -> str:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", edid_hex or "")
    if len(cleaned) < 256:
        return ""
    try:
        edid = bytes.fromhex(cleaned[:256])
    except ValueError:
        return ""
    name = ""
    serial = ""
    for offset in range(54, 109, 18):
        block = edid[offset : offset + 18]
        if len(block) < 18 or block[:3] != b"\x00\x00\x00":
            continue
        if block[3] == 0xFC:
            name = _decode_edid_text(block[5:18])
        elif block[3] == 0xFF:
            serial = _decode_edid_text(block[5:18])
    return _wmic_join([_decode_edid_vendor(edid), name, serial])


def _is_generic_monitor(value: str) -> bool:
    return bool(
        re.search(
            r"Generic\s+(?:Non-)?PnP\s+Monitor|Универсальный\s+монитор|Standard monitor types|Default_Monitor|NOEDID|Digital Flat Panel",
            value or "",
            re.IGNORECASE,
        )
    )


def _is_low_quality_monitor(value: str) -> bool:
    text = re.sub(r"\s+", " ", value or "").strip()
    if not text or _is_generic_monitor(text):
        return True
    return bool(re.fullmatch(r"[A-Z]{2}_?;\s*\d+", text, flags=re.IGNORECASE))


def _reg_query_edid(session: winrm.Session, pnp_device_id: str) -> str:
    if not pnp_device_id:
        return ""
    path = f"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\{pnp_device_id}\\Device Parameters"
    output, error = _run_remote_command(session, "reg", ["query", path, "/v", "EDID"])
    if error:
        return ""
    match = re.search(r"\bEDID\s+REG_BINARY\s+([0-9A-Fa-f\s]+)", output)
    return _decode_edid_monitor(match.group(1) if match else "")


def _is_active_wmi_value(value: Any) -> bool:
    return str(value or "").strip().lower() in {"true", "1", "yes"}


def _limited_values(values: list[str], max_items: int | None = None) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = _clean(value)
        if not cleaned:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(cleaned)
        if max_items and len(result) >= max_items:
            break
    return result


def _monitors_from_wmi_monitor_rows(rows: list[dict[str, str]], max_monitors: int | None = None) -> str:
    if not rows:
        return ""
    active_rows = [row for row in rows if _is_active_wmi_value(row.get("Active"))]
    rows_with_active_flag = [row for row in rows if row.get("Active") is not None]
    selected_rows = active_rows if active_rows else ([] if rows_with_active_flag else rows)
    monitors = []
    for row in selected_rows:
        friendly_name = _decode_wmi_char_array(row.get("UserFriendlyName"))
        monitor = _wmic_join(
            [
                _monitor_vendor(_decode_wmi_char_array(row.get("ManufacturerName"))),
                friendly_name,
                _decode_wmi_char_array(row.get("SerialNumberID")),
            ]
        )
        if monitor and friendly_name and not _is_low_quality_monitor(monitor):
            monitors.append(monitor)
    return _wmic_join(_limited_values(monitors, max_monitors))


def _collect_current_pnp_monitors_from_rows(
    session: winrm.Session,
    rows: list[dict[str, str]],
    max_monitors: int | None = None,
) -> str:
    monitors: list[str] = []
    for row in rows:
        pnp_device_id = row.get("PNPDeviceID") or ""
        if not pnp_device_id.upper().startswith("DISPLAY\\"):
            continue
        is_monitor = (row.get("Service") or "").lower() == "monitor" or pnp_device_id.upper().startswith("DISPLAY\\")
        error_code = str(row.get("ConfigManagerErrorCode") or "").strip()
        is_present = error_code in {"", "0"}
        if not is_monitor or not is_present:
            continue
        monitor = _reg_query_edid(session, pnp_device_id)
        fallback_name = _wmic_join([row.get("Manufacturer"), row.get("Name")])
        if not monitor and not _is_generic_monitor(fallback_name):
            monitor = fallback_name
        if monitor and not _is_generic_monitor(monitor):
            monitors.append(monitor)
    return _wmic_join(_limited_values(monitors, max_monitors))


def _collect_current_pnp_monitors_wsman(settings: Settings, target: str, session: winrm.Session) -> str:
    rows, _ = _wsman_wmi_query(settings, target, "root/cimv2", "Win32_PnPEntity")
    return _collect_current_pnp_monitors_from_rows(session, rows, settings.hardware_max_monitors)


def _display_ids_from_graphics_registry(session: winrm.Session) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()
    for subkey in ("Connectivity", "Configuration"):
        path = f"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\{subkey}"
        output, error = _run_remote_command(session, "reg", ["query", path, "/s"])
        if error:
            continue
        for raw in re.findall(r"DISPLAY\\([^\\\s]+)", output, flags=re.IGNORECASE):
            value = raw.strip()
            key = value.lower()
            if value and key not in seen and not _is_generic_monitor(value):
                seen.add(key)
                ids.append(value)
        for raw in re.findall(r"\\([A-Z]{3}[0-9A-F]{3,5})", output, flags=re.IGNORECASE):
            value = raw.strip()
            key = value.lower()
            if value and key not in seen and not _is_generic_monitor(value):
                seen.add(key)
                ids.append(value)
    return ids


def _collect_graphics_registry_monitors(session: winrm.Session, max_monitors: int | None = None) -> str:
    monitors: list[str] = []
    for display_id in _display_ids_from_graphics_registry(session):
        output, error = _run_remote_command(
            session,
            "reg",
            ["query", f"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\DISPLAY\\{display_id}", "/s", "/v", "EDID"],
        )
        if error:
            continue
        for match in re.finditer(r"\bEDID\s+REG_BINARY\s+([0-9A-Fa-f\s]+)", output):
            monitor = _decode_edid_monitor(match.group(1))
            if monitor and not _is_generic_monitor(monitor):
                monitors.append(monitor)
    return _wmic_join(_limited_values(monitors, max_monitors))


def _collect_current_pnp_monitors(session: winrm.Session, max_monitors: int | None = None) -> str:
    rows, _ = _wmic(
        session,
        [
            "path",
            "Win32_PnPEntity",
            "get",
            "ConfigManagerErrorCode,Manufacturer,Name,PNPDeviceID,Service",
            "/value",
        ],
    )
    return _collect_current_pnp_monitors_from_rows(session, rows, max_monitors)


def _collect_hardware_wsman(
    settings: Settings,
    target: str,
    session: winrm.Session,
    fallback_hostname: str,
) -> tuple[dict[str, str], str | None]:
    payload: dict[str, str] = {}
    system_rows, error = _wsman_wmi_query(settings, target, "root/cimv2", "Win32_ComputerSystem")
    if error:
        return {}, error
    system = system_rows[0] if system_rows else {}
    payload["hostname"] = _clean(system.get("Name")) or fallback_hostname

    cpu_rows, error = _wsman_wmi_query(settings, target, "root/cimv2", "Win32_Processor")
    if error:
        return {}, error
    payload["cpu"] = _wmic_join([row.get("Name") for row in cpu_rows])

    disk_rows, error = _wsman_wmi_query(settings, target, "root/cimv2", "Win32_DiskDrive")
    if error:
        return {}, error
    payload["disks"] = _wmic_join([_wmic_join([row.get("Model"), _bytes_to_gb(row.get("Size"))]) for row in disk_rows])

    gpu_rows, error = _wsman_wmi_query(settings, target, "root/cimv2", "Win32_VideoController")
    if error:
        return {}, error
    payload["gpu"] = _wmic_join([row.get("Name") for row in gpu_rows])

    board_rows, error = _wsman_wmi_query(settings, target, "root/cimv2", "Win32_BaseBoard")
    if error:
        return {}, error
    board = board_rows[0] if board_rows else {}
    payload["motherboard"] = _wmic_join([board.get("Manufacturer"), board.get("Product"), board.get("SerialNumber")])

    if settings.hardware_collect_memory_details:
        mem_array_rows, _ = _wsman_wmi_query(settings, target, "root/cimv2", "Win32_PhysicalMemoryArray")
        memory_rows, _ = _wsman_wmi_query(settings, target, "root/cimv2", "Win32_PhysicalMemory")
        total_ram = _bytes_to_gb(system.get("TotalPhysicalMemory"))
        slots = 0
        for row in mem_array_rows:
            try:
                slots += int(row.get("MemoryDevices") or 0)
            except ValueError:
                continue
        used = len([row for row in memory_rows if row.get("Capacity")])
        slot_summary = f"slots {used}/{slots} used, {max(0, slots - used)} free" if slots else (f"modules {used}" if used else "")
        modules = []
        for row in sorted(memory_rows, key=lambda item: (item.get("DeviceLocator") or "", item.get("BankLabel") or "")):
            speed = row.get("ConfiguredClockSpeed") or row.get("Speed")
            modules.append(
                _wmic_join(
                    [
                        _wmic_join([row.get("DeviceLocator"), row.get("BankLabel")]),
                        _bytes_to_gb(row.get("Capacity")),
                        f"{speed} MHz" if speed else "",
                        _wmic_join([row.get("Manufacturer"), row.get("PartNumber")]),
                    ]
                )
            )
        payload["ram"] = _wmic_join([total_ram, slot_summary, _wmic_join(modules)])

    if settings.hardware_collect_monitors:
        monitor_rows, _ = _wsman_wmi_query(settings, target, "root/wmi", "WmiMonitorID")
        payload["monitors"] = _monitors_from_wmi_monitor_rows(monitor_rows, settings.hardware_max_monitors)
        if not payload["monitors"]:
            payload["monitors"] = _collect_current_pnp_monitors_wsman(settings, target, session)
        if not payload["monitors"]:
            payload["monitors"] = _collect_graphics_registry_monitors(session, settings.hardware_max_monitors)

    if settings.hardware_collect_network_adapters:
        adapter_rows, _ = _wsman_wmi_query(settings, target, "root/cimv2", "Win32_NetworkAdapter")
        physical = [
            row
            for row in adapter_rows
            if str(row.get("PhysicalAdapter") or "").strip().lower() in {"true", "1"}
            and row.get("MACAddress")
            and not re.search(
                r"WAN Miniport|Kernel Debug|Bluetooth Device|Microsoft ISATAP|Teredo|Loopback",
                row.get("Name") or "",
                re.IGNORECASE,
            )
        ]
        connected = [row for row in physical if str(row.get("NetConnectionStatus") or "").strip() == "2"]
        adapters = []
        for row in sorted(physical, key=lambda item: (item.get("NetConnectionID") or "", item.get("Name") or "")):
            adapters.append(
                _wmic_join(
                    [
                        _wmic_join([row.get("NetConnectionID"), row.get("Name")]),
                        _wmic_adapter_status(row.get("NetConnectionStatus")),
                        _wmic_speed(row.get("Speed")),
                        row.get("MACAddress"),
                    ]
                )
            )
        payload["network"] = _wmic_join(
            [f"ports {len(connected)}/{len(physical)} connected" if physical else "", _wmic_join(adapters)]
        )

    return payload, None


def _collect_hardware_wmic(session: winrm.Session, settings: Settings, fallback_hostname: str) -> tuple[dict[str, str], str | None]:
    payload: dict[str, str] = {}
    system_rows, error = _wmic(session, ["computersystem", "get", "Name,TotalPhysicalMemory", "/value"])
    if error:
        return {}, error
    system = system_rows[0] if system_rows else {}
    payload["hostname"] = _clean(system.get("Name")) or fallback_hostname

    cpu_rows, error = _wmic(session, ["cpu", "get", "Name", "/value"])
    if error:
        return {}, error
    payload["cpu"] = _wmic_join([row.get("Name") for row in cpu_rows])

    disk_rows, error = _wmic(session, ["diskdrive", "get", "Model,Size", "/value"])
    if error:
        return {}, error
    payload["disks"] = _wmic_join([_wmic_join([row.get("Model"), _bytes_to_gb(row.get("Size"))]) for row in disk_rows])

    gpu_rows, error = _wmic(session, ["path", "Win32_VideoController", "get", "Name", "/value"])
    if error:
        return {}, error
    payload["gpu"] = _wmic_join([row.get("Name") for row in gpu_rows])

    board_rows, error = _wmic(session, ["baseboard", "get", "Manufacturer,Product,SerialNumber", "/value"])
    if error:
        return {}, error
    board = board_rows[0] if board_rows else {}
    payload["motherboard"] = _wmic_join([board.get("Manufacturer"), board.get("Product"), board.get("SerialNumber")])

    if settings.hardware_collect_memory_details:
        mem_array_rows, _ = _wmic(session, ["path", "Win32_PhysicalMemoryArray", "get", "MemoryDevices", "/value"])
        memory_rows, _ = _wmic(
            session,
            [
                "path",
                "Win32_PhysicalMemory",
                "get",
                "BankLabel,Capacity,ConfiguredClockSpeed,DeviceLocator,Manufacturer,PartNumber,Speed",
                "/value",
            ],
        )
        total_ram = _bytes_to_gb(system.get("TotalPhysicalMemory"))
        slots = 0
        for row in mem_array_rows:
            try:
                slots += int(row.get("MemoryDevices") or 0)
            except ValueError:
                continue
        used = len([row for row in memory_rows if row.get("Capacity")])
        slot_summary = f"slots {used}/{slots} used, {max(0, slots - used)} free" if slots else (f"modules {used}" if used else "")
        modules = []
        for row in sorted(memory_rows, key=lambda item: (item.get("DeviceLocator") or "", item.get("BankLabel") or "")):
            speed = row.get("ConfiguredClockSpeed") or row.get("Speed")
            modules.append(
                _wmic_join(
                    [
                        _wmic_join([row.get("DeviceLocator"), row.get("BankLabel")]),
                        _bytes_to_gb(row.get("Capacity")),
                        f"{speed} MHz" if speed else "",
                        _wmic_join([row.get("Manufacturer"), row.get("PartNumber")]),
                    ]
                )
            )
        payload["ram"] = _wmic_join([total_ram, slot_summary, _wmic_join(modules)])

    if settings.hardware_collect_monitors:
        monitor_rows, _ = _wmic(
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
        payload["monitors"] = _monitors_from_wmi_monitor_rows(monitor_rows, settings.hardware_max_monitors)
        if not payload["monitors"]:
            payload["monitors"] = _collect_current_pnp_monitors(session, settings.hardware_max_monitors)
        if not payload["monitors"]:
            payload["monitors"] = _collect_graphics_registry_monitors(session, settings.hardware_max_monitors)

    if settings.hardware_collect_network_adapters:
        adapter_rows, _ = _wmic(
            session,
            [
                "path",
                "Win32_NetworkAdapter",
                "get",
                "MACAddress,Name,NetConnectionID,NetConnectionStatus,PhysicalAdapter,Speed",
                "/value",
            ],
        )
        physical = [
            row
            for row in adapter_rows
            if str(row.get("PhysicalAdapter") or "").strip().lower() in {"true", "1"}
            and row.get("MACAddress")
            and not re.search(
                r"WAN Miniport|Kernel Debug|Bluetooth Device|Microsoft ISATAP|Teredo|Loopback",
                row.get("Name") or "",
                re.IGNORECASE,
            )
        ]
        connected = [row for row in physical if str(row.get("NetConnectionStatus") or "").strip() == "2"]
        adapters = []
        for row in sorted(physical, key=lambda item: (item.get("NetConnectionID") or "", item.get("Name") or "")):
            adapters.append(
                _wmic_join(
                    [
                        _wmic_join([row.get("NetConnectionID"), row.get("Name")]),
                        _wmic_adapter_status(row.get("NetConnectionStatus")),
                        _wmic_speed(row.get("Speed")),
                        row.get("MACAddress"),
                    ]
                )
            )
        payload["network"] = _wmic_join(
            [f"ports {len(connected)}/{len(physical)} connected" if physical else "", _wmic_join(adapters)]
        )

    return payload, None


def _collect_monitor_only_fallback(
    session: winrm.Session,
    settings: Settings,
    target: str,
    fallback_hostname: str,
) -> tuple[dict[str, str], str | None]:
    if not settings.hardware_collect_monitors:
        return {}, "monitor collection is disabled"
    monitors = _collect_current_pnp_monitors_wsman(settings, target, session)
    if not monitors:
        monitors = _collect_current_pnp_monitors(session, settings.hardware_max_monitors)
    if not monitors:
        monitors = _collect_graphics_registry_monitors(session, settings.hardware_max_monitors)
    if not monitors:
        return {}, "monitor fallback found no active displays"
    return {"hostname": fallback_hostname, "monitors": monitors}, None


def _run_powershell(session: winrm.Session, script: str):
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return session.run_cmd(
        "powershell.exe",
        [
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded,
        ],
    )


def _run_hardware_script(session: winrm.Session, script: str) -> tuple[dict[str, Any], str | None]:
    result = _run_powershell(session, script)
    if result.status_code != 0:
        error = _clean_winrm_error(result.std_err or b"")
        return {}, error or f"WinRM returned {result.status_code}"

    output = (result.std_out or b"").decode("utf-8-sig", errors="replace").strip()
    if not output:
        return {}, "empty WinRM response"
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        return {}, f"invalid JSON from WinRM: {exc}"
    if not isinstance(payload, dict):
        return {}, "invalid JSON shape from WinRM"
    return payload, None


def collect_hardware_for_computer(settings: Settings, computer: dict[str, Any]) -> tuple[str, str, dict[str, str] | None, str | None]:
    hostname = _computer_hostname(computer) or ""
    target = _computer_target(computer)
    if not target:
        return hostname, "", None, "missing hostname"
    if settings.hardware_winrm_precheck_enabled and not _tcp_port_reachable(
        target,
        settings.hardware_winrm_port,
        settings.hardware_winrm_precheck_timeout_seconds,
    ):
        return hostname, target, None, f"WinRM port {settings.hardware_winrm_port} is not reachable"

    session = winrm.Session(
        _endpoint(settings, target),
        auth=(settings.hardware_winrm_user, settings.hardware_winrm_password),
        transport=settings.hardware_winrm_transport,
        server_cert_validation=settings.hardware_winrm_server_cert_validation,
        operation_timeout_sec=settings.hardware_winrm_operation_timeout_seconds,
        read_timeout_sec=settings.hardware_winrm_read_timeout_seconds,
    )
    payload: dict[str, Any] = {}
    try:
        if settings.hardware_collection_mode == "wmic":
            payload, error = _collect_hardware_wsman(settings, target, session, hostname)
            if error:
                logger.debug("WSMan WMI collection failed for %s, falling back to wmic.exe: %s", target, error)
                payload, error = _collect_hardware_wmic(session, settings, hostname)
            if error:
                monitor_payload, monitor_error = _collect_monitor_only_fallback(session, settings, target, hostname)
                if monitor_payload:
                    logger.info(
                        "Hardware core collection failed for %s, saved monitor-only fallback: %s",
                        target,
                        error,
                    )
                    payload = monitor_payload
                else:
                    return hostname, target, None, f"{error}; monitor fallback: {monitor_error}"
        else:
            for section_name, script, required in enabled_hardware_scripts(settings):
                section_payload, error = _run_hardware_script(session, script)
                if error:
                    if required:
                        return hostname, target, None, error
                    logger.debug("Optional hardware section %s not collected for %s: %s", section_name, target, error)
                    continue
                payload.update(section_payload)
    except Exception as exc:
        return hostname, target, None, str(exc)

    return hostname, target, {
        "hostname": _clean(payload.get("hostname")) or hostname,
        "cpu": _clean(payload.get("cpu")) or "",
        "ram": _clean(payload.get("ram")) or "",
        "disks": _clean(payload.get("disks")) or "",
        "gpu": _clean(payload.get("gpu")) or "",
        "motherboard": _clean(payload.get("motherboard")) or "",
        "monitors": _clean(payload.get("monitors")) or "",
        "network": _clean(payload.get("network")) or "",
    }, None


def save_hardware(
    db: Session,
    hostname: str,
    source_type: str,
    payload: dict[str, str],
    machine_id: int | None = None,
    ip_address: str | None = None,
) -> None:
    normalized = normalize_hostname(hostname)
    if not normalized:
        return

    machine = db.get(Machine, machine_id) if machine_id else None
    if machine is None:
        machine = db.scalar(select(Machine).where(Machine.normalized_hostname == normalized))
    if machine is None and ip_address:
        machine = db.scalar(select(Machine).where(Machine.source_type == source_type, Machine.ip_address == ip_address))
    if machine is None:
        machine = Machine(
            hostname=hostname.upper(),
            normalized_hostname=normalized,
            source_type=source_type,
            match_status="hardware_report",
            match_score=0,
            match_note="created by hardware collector",
        )
        db.add(machine)

    machine.hardware_cpu = payload.get("cpu") or machine.hardware_cpu
    machine.hardware_ram = payload.get("ram") or machine.hardware_ram
    machine.hardware_disks = payload.get("disks") or machine.hardware_disks
    machine.hardware_gpu = payload.get("gpu") or machine.hardware_gpu
    machine.hardware_motherboard = payload.get("motherboard") or machine.hardware_motherboard
    machine.hardware_monitors = payload.get("monitors") or None
    machine.hardware_network = payload.get("network") or machine.hardware_network
    machine.hardware_updated_at = dt.datetime.now(dt.timezone.utc)


def clear_existing_hardware(db: Session) -> int:
    cleared = 0
    for machine in db.scalars(select(Machine).where(or_(Machine.source_type.is_(None), Machine.source_type != "printer"))).all():
        if machine.source_type in {"switch", "wifi", "network"}:
            continue
        if not any(
            (
                machine.hardware_cpu,
                machine.hardware_ram,
                machine.hardware_disks,
                machine.hardware_gpu,
                machine.hardware_motherboard,
                machine.hardware_monitors,
                machine.hardware_network,
            )
        ):
            continue
        machine.hardware_cpu = None
        machine.hardware_ram = None
        machine.hardware_disks = None
        machine.hardware_gpu = None
        machine.hardware_motherboard = None
        machine.hardware_monitors = None
        machine.hardware_network = None
        machine.hardware_updated_at = None
        cleared += 1
    db.commit()
    return cleared


def _network_server_computers(db: Session, settings: Settings) -> list[dict[str, str]]:
    if not settings.hardware_collect_network_servers:
        return []
    rows = db.scalars(select(Machine).where(Machine.source_type == "server", Machine.is_active.is_(True))).all()
    computers: list[dict[str, str]] = []
    for machine in rows:
        target = _clean(machine.dns_hostname) or _clean(machine.ip_address) or _clean(machine.hostname)
        hostname = _clean(machine.hostname)
        if not target or not hostname:
            continue
        computers.append(
            {
                "machine_id": str(machine.id),
                "name": hostname,
                "cn": hostname,
                "dNSHostName": machine.dns_hostname or "",
                "ip_address": machine.ip_address or "",
                "source_type": "server",
            }
        )
    return computers


def _dedupe_computers(computers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for computer in computers:
        key = normalize_hostname(_computer_target(computer) or _computer_hostname(computer))
        if not key:
            continue
        deduped[key] = computer
    return list(deduped.values())


def run_hardware_collection(db: Session) -> tuple[int, int, int]:
    settings = get_settings()
    if not settings.hardware_collector_enabled:
        logger.info("Hardware collector is disabled; set HARDWARE_COLLECTOR_ENABLED=true")
        return 0, 0, 0
    if not settings.hardware_winrm_user or not settings.hardware_winrm_password:
        logger.warning("Hardware collector is enabled but HARDWARE_WINRM_USER/HARDWARE_WINRM_PASSWORD is empty")
        return 0, 0, 0
    logger.info(
        "Hardware collector mode=%s sections enabled memory=%s monitors=%s network_adapters=%s",
        settings.hardware_collection_mode,
        settings.hardware_collect_memory_details,
        settings.hardware_collect_monitors,
        settings.hardware_collect_network_adapters,
    )

    computers: list[dict[str, Any]] = []
    try:
        with ActiveDirectoryClient(settings) as ad:
            computers = ad.load_computers()
    except Exception as exc:
        logger.warning("Hardware collector could not load AD computers: %s", exc)

    network_servers = _network_server_computers(db, settings)
    if network_servers:
        logger.info("Hardware collector added network servers=%s", len(network_servers))
        computers.extend(network_servers)
    computers = _dedupe_computers(computers)

    if not computers:
        logger.warning("Hardware collector found 0 computers/servers to process")
        return 0, 0, 0

    if settings.hardware_clear_before_collection:
        cleared = clear_existing_hardware(db)
        logger.info("Cleared existing hardware fields before collection rows=%s", cleared)

    collected = 0
    failed = 0
    max_workers = max(1, min(settings.hardware_collect_workers, len(computers)))
    logger.info("Hardware collection started computers=%s workers=%s", len(computers), max_workers)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(collect_hardware_for_computer, settings, computer): computer for computer in computers}
        for index, future in enumerate(as_completed(future_map), start=1):
            computer = future_map[future]
            source_type = computer.get("source_type") or "physical"
            try:
                hostname, target, payload, error = future.result()
            except Exception as exc:
                failed += 1
                logger.warning("Hardware collection failed for %s: %s", _computer_target(computer), exc)
                continue
            if error or not payload:
                failed += 1
                if error and "not reachable" in error:
                    logger.info("Hardware unreachable for %s: %s", target or hostname, error)
                else:
                    logger.info("Hardware not collected for %s: %s", target or hostname, error)
            else:
                machine_id_raw = computer.get("machine_id")
                try:
                    machine_id = int(machine_id_raw) if machine_id_raw else None
                except (TypeError, ValueError):
                    machine_id = None
                save_hardware(
                    db,
                    hostname or payload["hostname"],
                    source_type,
                    payload,
                    machine_id=machine_id,
                    ip_address=_clean(computer.get("ip_address")),
                )
                collected += 1
            if index % 25 == 0:
                db.commit()
                logger.info("Hardware collection progress: %s/%s collected=%s failed=%s", index, len(computers), collected, failed)

    db.commit()
    logger.info("Hardware collection completed seen=%s collected=%s failed=%s", len(computers), collected, failed)
    return len(computers), collected, failed


def main() -> None:
    settings = get_settings()
    configure_timezone(settings.app_timezone)
    configure_logging(settings.app_timezone)
    init_db()
    logger.info("Hardware collector loop started; interval=%s seconds", settings.hardware_collection_interval_seconds)
    while True:
        with SessionLocal() as db:
            run_hardware_collection(db)
        time.sleep(settings.hardware_collection_interval_seconds)


if __name__ == "__main__":
    main()
