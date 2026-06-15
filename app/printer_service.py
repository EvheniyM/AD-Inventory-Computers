from __future__ import annotations

import csv
import ipaddress
import logging
import random
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import unescape
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.matcher import normalize_hostname
from app.models import Machine


SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
PRT_GENERAL_PRINTER_NAME_BASE = "1.3.6.1.2.1.43.5.1.1.16.1"
PRT_GENERAL_PRINTER_NAME_OIDS = (
    PRT_GENERAL_PRINTER_NAME_BASE,
    f"{PRT_GENERAL_PRINTER_NAME_BASE}.1",
    f"{PRT_GENERAL_PRINTER_NAME_BASE}.2",
)
HR_DEVICE_DESCR_OIDS = tuple(f"1.3.6.1.2.1.25.3.2.1.3.{index}" for index in range(1, 65))

GENERIC_NAME_RE = re.compile(
    r"^(NPI|DEV|HRK|BRN|RNP|XRX|KM|KMBT|NP|CN)[A-Z0-9_-]{5,}$|^[0-9A-F]{8,12}$",
    re.IGNORECASE,
)
HTML_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
IP_ADDRESS_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
BAD_HTTP_TITLES = {
    "home",
    "login",
    "remote ui",
    "web image monitor",
    "printer",
    "multifunction printer",
    "device status",
}
MODEL_PATTERNS = (
    re.compile(
        r"\b(?:Series|Model|Product\s+Name|Device\s+Name)\s*[:：-]\s*"
        r"(?P<model>(?:Canon\s+)?(?:i-SENSYS\s+)?(?:MF|LBP)\s*-?\s*\d[A-Za-z0-9-]*(?:\s+Series)?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?P<model>(?:Canon\s+)?(?:i-SENSYS\s+)?(?:MF|LBP)\s*-?\s*\d[A-Za-z0-9-]*(?:\s+Series)?)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?P<model>(?:Canon\s+)?PIXMA\s+[A-Za-z0-9-]+(?:\s+Series)?)\b", re.IGNORECASE),
    re.compile(r"\b(?P<model>(?:Xerox\s+)?WorkCentre\W+\d{3,5}[A-Za-z0-9-]*)\b", re.IGNORECASE),
    re.compile(r"\b(?P<model>(?:Xerox\s+)?VersaLink\W+[A-Za-z0-9-]{2,20})\b", re.IGNORECASE),
    re.compile(r"\b(?P<model>(?:Xerox\s+)?Phaser\W+\d{3,5}[A-Za-z0-9-]*)\b", re.IGNORECASE),
    re.compile(r"\b(?P<model>HP\s+(?:Color\s+)?LaserJet(?:\s+Pro)?(?:\s+MFP)?\s+[A-Za-z0-9-]+)\b", re.IGNORECASE),
    re.compile(r"\b(?P<model>HP\s+(?:OfficeJet|DeskJet)(?:\s+Pro)?\s+[A-Za-z0-9-]+)\b", re.IGNORECASE),
    re.compile(r"\b(?P<model>(?:KYOCERA\s+)?(?:ECOSYS|TASKalfa)\s+[A-Za-z0-9-]+)\b", re.IGNORECASE),
    re.compile(r"\b(?P<model>Brother\s+[A-Za-z0-9-]{2,30})\b", re.IGNORECASE),
    re.compile(r"\b(?P<model>RICOH\s+[A-Za-z0-9-]{2,30})\b", re.IGNORECASE),
    re.compile(r"\b(?P<model>KONICA\s+MINOLTA\s+[A-Za-z0-9-]{2,30})\b", re.IGNORECASE),
    re.compile(r"\b(?P<model>Samsung\s+[A-Za-z0-9-]{2,30})\b", re.IGNORECASE),
)
SOURCE_PRIORITY = {"tcp": 5, "snmp": 10, "tcp_named": 15, "http": 20, "csv": 30}


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _split_csv(value: str) -> list[str]:
    return [item.strip().lower() for item in value.split(",") if item.strip()]


def _split_csv_int(value: str) -> list[int]:
    ports: list[int] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            port = int(item)
        except ValueError:
            continue
        if 0 < port <= 65535:
            ports.append(port)
    return ports


def _strip_ip_from_name(value: str) -> str:
    cleaned = IP_ADDRESS_RE.sub("", value)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip(" -\t\r\n")


def _strip_service_title_labels(value: str) -> str:
    cleaned = _strip_ip_from_name(value.replace("\xa0", " "))
    cleaned = re.sub(r"[®™©]", "", cleaned)
    for _ in range(4):
        before = cleaned
        cleaned = re.sub(r"^(?:Remote\s*UI|Web\s*Image\s*Monitor)\s*[:：-]\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"^Удал[её]нн\w+\s+\S+\s*[:：-]\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"^(?:Login|Log\s*In|Вход|Вхід)\s*[:：-]\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(
            r"^(?:Series|Model|Product\s+Name|Device\s+Name|Product|Device)\s*[:：-]\s*",
            "",
            cleaned,
            flags=re.IGNORECASE,
        )
        cleaned = cleaned.strip(" -:：|;,\t\r\n")
        if cleaned == before:
            break
    return re.sub(r"\s+", " ", cleaned).strip(" -:：|;,\t\r\n")


def _printer_key(name: str, ip_address: str) -> str:
    return normalize_hostname(f"printer-{name}-{ip_address}")


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _encode_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(value)) + value


def _encode_integer(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True)
    return _encode_tlv(0x02, raw)


def _encode_octet_string(value: str) -> bytes:
    return _encode_tlv(0x04, value.encode("utf-8"))


def _encode_null() -> bytes:
    return _encode_tlv(0x05, b"")


def _encode_oid(oid: str) -> bytes:
    parts = [int(part) for part in oid.split(".")]
    encoded = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        stack = [part & 0x7F]
        part >>= 7
        while part:
            stack.append(0x80 | (part & 0x7F))
            part >>= 7
        encoded += bytes(reversed(stack))
    return _encode_tlv(0x06, encoded)


def _encode_sequence(value: bytes) -> bytes:
    return _encode_tlv(0x30, value)


def _build_snmp_request(oid: str, community: str, request_id: int, pdu_tag: int, version: int = 1) -> bytes:
    varbind = _encode_sequence(_encode_oid(oid) + _encode_null())
    varbind_list = _encode_sequence(varbind)
    pdu = _encode_tlv(pdu_tag, _encode_integer(request_id) + _encode_integer(0) + _encode_integer(0) + varbind_list)
    return _encode_sequence(_encode_integer(version) + _encode_octet_string(community) + pdu)


def _read_length(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    return int.from_bytes(data[offset : offset + count], "big"), offset + count


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    tag = data[offset]
    length, value_offset = _read_length(data, offset + 1)
    end = value_offset + length
    return tag, data[value_offset:end], end


def _decode_value(tag: int, value: bytes) -> str:
    if tag == 0x04:
        return value.decode("utf-8", errors="replace").strip("\x00").strip()
    if tag == 0x02:
        return str(int.from_bytes(value, "big", signed=True))
    if tag == 0x06:
        return ".".join(str(part) for part in _decode_oid_value(value))
    if tag == 0x40 and len(value) == 4:
        return ".".join(str(part) for part in value)
    if tag in {0x41, 0x42, 0x43, 0x46, 0x47}:
        return str(int.from_bytes(value, "big", signed=False))
    return value.decode("utf-8", errors="replace").strip("\x00").strip()


def _decode_oid_value(value: bytes) -> list[int]:
    if not value:
        return []
    first = value[0]
    parts = [first // 40, first % 40]
    current = 0
    for byte in value[1:]:
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(current)
            current = 0
    return parts


def _parse_response_varbind(data: bytes) -> tuple[str, str] | None:
    tag, message, _ = _read_tlv(data, 0)
    if tag != 0x30:
        return None

    offset = 0
    _, _, offset = _read_tlv(message, offset)
    _, _, offset = _read_tlv(message, offset)
    pdu_tag, pdu, offset = _read_tlv(message, offset)
    if pdu_tag != 0xA2:
        return None

    pdu_offset = 0
    _, _, pdu_offset = _read_tlv(pdu, pdu_offset)
    _, error_status_raw, pdu_offset = _read_tlv(pdu, pdu_offset)
    _, _, pdu_offset = _read_tlv(pdu, pdu_offset)
    if int.from_bytes(error_status_raw, "big", signed=True) != 0:
        return None

    list_tag, varbind_list, _ = _read_tlv(pdu, pdu_offset)
    if list_tag != 0x30:
        return None
    bind_tag, varbind, _ = _read_tlv(varbind_list, 0)
    if bind_tag != 0x30:
        return None
    bind_offset = 0
    _, oid_raw, bind_offset = _read_tlv(varbind, bind_offset)
    value_tag, value_raw, _ = _read_tlv(varbind, bind_offset)
    if value_tag == 0x05:
        return None
    return ".".join(str(part) for part in _decode_oid_value(oid_raw)), _decode_value(value_tag, value_raw)


def _parse_get_response(data: bytes) -> str | None:
    parsed = _parse_response_varbind(data)
    if parsed is None:
        return None
    _, value = parsed
    return value


def snmp_get(
    ip_address: str,
    oid: str,
    community: str,
    port: int,
    timeout_seconds: float,
    versions: tuple[int, ...] = (1,),
) -> str | None:
    last_error: OSError | TimeoutError | None = None
    for version in versions:
        request = _build_snmp_request(oid, community, random.randint(1, 2_000_000_000), 0xA0, version)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout_seconds)
                sock.sendto(request, (ip_address, port))
                data, _ = sock.recvfrom(65535)
        except (OSError, TimeoutError) as exc:
            last_error = exc
            continue
        value = _parse_get_response(data)
        if value:
            return value
    if last_error is not None:
        raise last_error
    return None


def snmp_getnext(
    ip_address: str,
    oid: str,
    community: str,
    port: int,
    timeout_seconds: float,
) -> tuple[str, str] | None:
    request = _build_snmp_request(oid, community, random.randint(1, 2_000_000_000), 0xA1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout_seconds)
        sock.sendto(request, (ip_address, port))
        data, _ = sock.recvfrom(65535)
    return _parse_response_varbind(data)


def _first_snmp_value(ip_address: str, oids: tuple[str, ...], settings: Settings) -> str:
    for oid in oids:
        try:
            value = snmp_get(
                ip_address,
                oid,
                settings.printer_snmp_community,
                settings.printer_snmp_port,
                settings.printer_snmp_timeout_seconds,
            )
        except (OSError, TimeoutError):
            continue
        if value:
            return value
    return ""


def _first_snmp_table_value(ip_address: str, base_oid: str, settings: Settings, limit: int = 8) -> str:
    current_oid = base_oid
    prefix = f"{base_oid}."
    for _ in range(limit):
        try:
            result = snmp_getnext(
                ip_address,
                current_oid,
                settings.printer_snmp_community,
                settings.printer_snmp_port,
                settings.printer_snmp_timeout_seconds,
            )
        except (OSError, TimeoutError):
            return ""
        if result is None:
            return ""
        next_oid, value = result
        if next_oid != base_oid and not next_oid.startswith(prefix):
            return ""
        if value:
            return value
        current_oid = next_oid
    return ""


def _is_printer(printer_name: str, name: str, description: str, hr_description: str, settings: Settings) -> bool:
    text = f"{printer_name} {name} {description} {hr_description}".lower()
    include_keywords = _split_csv(settings.printer_snmp_include_keywords)
    exclude_keywords = _split_csv(settings.printer_snmp_exclude_keywords)
    if any(keyword and keyword in text for keyword in exclude_keywords):
        return False
    if not settings.printer_snmp_require_keywords:
        return True
    return any(keyword and keyword in text for keyword in include_keywords)


def _looks_generic_name(value: str, ip_address: str) -> bool:
    cleaned = _clean(value)
    if not cleaned:
        return True
    if cleaned.lower() in {"unknown", ip_address}:
        return True
    compact = re.sub(r"[^A-Za-z0-9]", "", cleaned)
    return bool(GENERIC_NAME_RE.match(compact))


def _name_from_description(description: str) -> str:
    cleaned = _strip_service_title_labels(re.sub(r"\s+", " ", _clean(description)))
    if not cleaned:
        return ""
    for separator in (";", " SN:", " Serial", " Firmware", " Version"):
        if separator in cleaned:
            cleaned = cleaned.split(separator, 1)[0].strip()
    return cleaned[:120]


def _model_from_text(value: str) -> str:
    text = _strip_ip_from_name(unescape(re.sub(r"<[^>]+>", " ", value)))
    text = re.sub(r"[®™©]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    candidates: list[str] = []
    for pattern in MODEL_PATTERNS:
        for match in pattern.finditer(text):
            model = match.groupdict().get("model") or match.group(0)
            model = _strip_service_title_labels(model)
            model = re.sub(r"\s+", " ", model).strip(" -|:;,")
            if model:
                candidates.append(model[:120])
    if not candidates:
        return ""

    def score(candidate: str) -> tuple[int, int]:
        lower = candidate.lower()
        value = len(candidate)
        if re.search(r"\d", candidate):
            value += 40
        if "series" in lower:
            value += 20
        if re.search(r"\b(?:mfp|laserjet|workcentre|versalink|phaser|ecosys|taskalfa)\b", lower):
            value += 15
        if re.search(r"\b(?:mf|lbp)\s*-?\s*\d", lower):
            value += 15
        return value, len(candidate)

    return max(candidates, key=score)


def _clean_http_title(value: str) -> str:
    cleaned = unescape(re.sub(r"\s+", " ", value)).strip(" -\t\r\n")
    cleaned = re.sub(r"\s*\|\s*.*$", "", cleaned).strip()
    cleaned = re.sub(r"\s+-\s+(Remote UI|Web Image Monitor|Status|Login).*$", "", cleaned, flags=re.IGNORECASE).strip()
    cleaned = _strip_service_title_labels(cleaned)
    return cleaned[:120]


def _http_printer_name(ip_address: str, settings: Settings) -> str:
    if not settings.printer_http_name_enabled:
        return ""
    context = ssl._create_unverified_context()
    for raw_port in settings.printer_http_name_ports.split(","):
        port_text = raw_port.strip()
        if not port_text:
            continue
        try:
            port = int(port_text)
        except ValueError:
            continue
        schemes = ("https", "http") if port in {443, 8443} else ("http",)
        for scheme in schemes:
            base_url = f"{scheme}://{ip_address}"
            if not (scheme == "http" and port == 80) and not (scheme == "https" and port == 443):
                base_url = f"{base_url}:{port}"
            for raw_path in settings.printer_http_name_paths.split(","):
                path = raw_path.strip() or "/"
                if not path.startswith("/"):
                    path = f"/{path}"
                try:
                    request = Request(f"{base_url}{path}", headers={"User-Agent": "BARS-Inventory/1.0"})
                    with urlopen(
                        request,
                        timeout=settings.printer_http_name_timeout_seconds,
                        context=context,
                    ) as response:
                        body = response.read(262144).decode("utf-8", errors="replace")
                except (OSError, HTTPError, URLError, TimeoutError, ValueError):
                    continue
                match = HTML_TITLE_RE.search(body)
                title = _clean_http_title(match.group(1)) if match else ""

                model = _model_from_text(f"{title} {body}")
                if model and not _looks_generic_name(model, ip_address):
                    return model

                if title and title.lower() not in BAD_HTTP_TITLES and not _looks_generic_name(title, ip_address):
                    return title
    return ""


def _reverse_dns_name(ip_address: str, settings: Settings) -> str:
    if not settings.printer_reverse_dns_enabled:
        return ""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
    except (OSError, socket.herror, socket.gaierror):
        return ""
    short_name = hostname.split(".", 1)[0]
    if _looks_generic_name(short_name, ip_address):
        return ""
    return _strip_ip_from_name(short_name)[:120]


def _http_name_is_printer(name: str, settings: Settings) -> bool:
    text = name.lower()
    include_keywords = _split_csv(settings.printer_snmp_include_keywords)
    exclude_keywords = _split_csv(settings.printer_snmp_exclude_keywords)
    if any(keyword and keyword in text for keyword in exclude_keywords):
        return False
    if not settings.printer_http_require_keywords:
        return True
    return any(keyword and keyword in text for keyword in include_keywords)


def _display_name(
    ip_address: str,
    http_name: str,
    printer_name: str,
    name: str,
    description: str,
    hr_description: str,
) -> str:
    combined_text = " ".join([http_name, printer_name, name, description, hr_description])
    model_name = _model_from_text(combined_text)
    clean_http_name = _strip_service_title_labels(http_name)
    candidates = [model_name, clean_http_name, _name_from_description(hr_description), _name_from_description(description)]
    if not _looks_generic_name(printer_name, ip_address):
        candidates.append(printer_name)
    if not _looks_generic_name(name, ip_address):
        candidates.append(name)
    candidates.append(printer_name)
    candidates.append(name)

    for value in candidates:
        cleaned = _strip_ip_from_name(_clean(value))
        if cleaned and cleaned.lower() not in {"unknown", ip_address} and not _looks_generic_name(cleaned, ip_address):
            return cleaned[:120]
    for value in candidates:
        cleaned = _strip_ip_from_name(_clean(value))
        if cleaned and cleaned.lower() not in {"unknown", ip_address}:
            return cleaned[:120]
    return f"Printer {ip_address}"


def _scan_printer_ip(ip_address: str, settings: Settings) -> dict[str, str] | None:
    try:
        name = snmp_get(
            ip_address,
            SYS_NAME,
            settings.printer_snmp_community,
            settings.printer_snmp_port,
            settings.printer_snmp_timeout_seconds,
        ) or ""
        description = snmp_get(
            ip_address,
            SYS_DESCR,
            settings.printer_snmp_community,
            settings.printer_snmp_port,
            settings.printer_snmp_timeout_seconds,
        ) or ""
    except (OSError, TimeoutError):
        return None

    try:
        printer_name = _first_snmp_value(
            ip_address,
            PRT_GENERAL_PRINTER_NAME_OIDS,
            settings,
        ) or _first_snmp_table_value(ip_address, PRT_GENERAL_PRINTER_NAME_BASE, settings)
    except (OSError, TimeoutError):
        printer_name = ""

    hr_description = _first_snmp_value(ip_address, HR_DEVICE_DESCR_OIDS, settings)

    if not name and not description and not printer_name and not hr_description:
        return None
    if not _is_printer(printer_name, name, description, hr_description, settings):
        return None

    try:
        location = snmp_get(
            ip_address,
            SYS_LOCATION,
            settings.printer_snmp_community,
            settings.printer_snmp_port,
            settings.printer_snmp_timeout_seconds,
        ) or ""
    except (OSError, TimeoutError):
        location = ""

    http_name = _http_printer_name(ip_address, settings)
    display_name = _display_name(ip_address, http_name, printer_name, name, description, hr_description)
    note_parts = [f"SNMP: sysName={name}"]
    if printer_name:
        note_parts.append(f"printerName={printer_name}")
    if hr_description:
        note_parts.append(f"hrDeviceDescr={hr_description[:120]}")
    if description:
        note_parts.append(description[:160])
    return {
        "name": display_name,
        "ip_address": ip_address,
        "location": _clean(location),
        "note": "; ".join(note_parts),
        "source": "snmp",
    }


def _iter_subnet_hosts(subnets: str, max_hosts: int, logger: logging.Logger | None = None) -> list[str]:
    hosts: list[str] = []
    for raw in subnets.split(","):
        value = raw.strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            if logger:
                logger.warning("Invalid printer SNMP subnet skipped: %s (%s)", value, exc)
            continue
        for address in network.hosts():
            hosts.append(str(address))
            if len(hosts) >= max_hosts:
                return hosts
    return hosts


def discover_snmp_printers(settings: Settings, logger: logging.Logger | None = None) -> list[dict[str, str]]:
    if not settings.printer_snmp_discovery_enabled or not settings.printer_snmp_subnets.strip():
        return []

    log = logger or logging.getLogger(__name__)
    targets = _iter_subnet_hosts(settings.printer_snmp_subnets, settings.printer_snmp_max_hosts, log)
    if not targets:
        return []

    max_workers = max(1, min(settings.printer_snmp_workers, len(targets)))
    log.info("SNMP printer discovery started targets=%s workers=%s", len(targets), max_workers)

    rows: list[dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(_scan_printer_ip, ip_address, settings): ip_address for ip_address in targets}
        for index, future in enumerate(as_completed(future_map), start=1):
            ip_address = future_map[future]
            try:
                row = future.result()
            except Exception as exc:
                log.debug("SNMP scan failed for %s: %s", ip_address, exc)
                continue
            if row:
                rows.append(row)
                log.info("SNMP printer found ip=%s name=%s", row["ip_address"], row["name"])
            if index % 256 == 0:
                log.info("SNMP printer discovery progress: %s/%s found=%s", index, len(targets), len(rows))
    log.info("SNMP printer discovery completed targets=%s found=%s", len(targets), len(rows))
    return rows


def _scan_http_printer_ip(ip_address: str, settings: Settings) -> dict[str, str] | None:
    name = _http_printer_name(ip_address, settings)
    if not name or not _http_name_is_printer(name, settings):
        return None
    return {
        "name": name,
        "ip_address": ip_address,
        "location": "",
        "note": f"HTTP discovery: {name}",
        "source": "http",
    }


def discover_http_printers(settings: Settings, logger: logging.Logger | None = None) -> list[dict[str, str]]:
    if (
        not settings.printer_http_discovery_enabled
        or not settings.printer_http_name_enabled
        or not settings.printer_snmp_subnets.strip()
    ):
        return []

    log = logger or logging.getLogger(__name__)
    targets = _iter_subnet_hosts(settings.printer_snmp_subnets, settings.printer_snmp_max_hosts, log)
    if not targets:
        return []

    max_workers = max(1, min(settings.printer_snmp_workers, len(targets)))
    log.info("HTTP printer discovery started targets=%s workers=%s", len(targets), max_workers)

    rows: list[dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(_scan_http_printer_ip, ip_address, settings): ip_address for ip_address in targets}
        for index, future in enumerate(as_completed(future_map), start=1):
            ip_address = future_map[future]
            try:
                row = future.result()
            except Exception as exc:
                log.debug("HTTP scan failed for %s: %s", ip_address, exc)
                continue
            if row:
                rows.append(row)
                log.info("HTTP printer found ip=%s name=%s", row["ip_address"], row["name"])
            if index % 256 == 0:
                log.info("HTTP printer discovery progress: %s/%s found=%s", index, len(targets), len(rows))
    log.info("HTTP printer discovery completed targets=%s found=%s", len(targets), len(rows))
    return rows


def _tcp_port_open(ip_address: str, port: int, timeout_seconds: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout_seconds)
        try:
            return sock.connect_ex((ip_address, port)) == 0
        except OSError:
            return False


def _scan_tcp_printer_ip(ip_address: str, settings: Settings) -> dict[str, str] | None:
    open_ports = [
        port
        for port in _split_csv_int(settings.printer_tcp_ports)
        if _tcp_port_open(ip_address, port, settings.printer_tcp_timeout_seconds)
    ]
    if not open_ports:
        return None

    http_name = _http_printer_name(ip_address, settings)
    dns_name = _reverse_dns_name(ip_address, settings)
    name = http_name or dns_name or f"Printer {ip_address}"
    return {
        "name": name,
        "ip_address": ip_address,
        "location": "",
        "note": f"TCP discovery: open ports={','.join(str(port) for port in open_ports)}",
        "source": "tcp_named" if http_name or dns_name else "tcp",
    }


def discover_tcp_printers(settings: Settings, logger: logging.Logger | None = None) -> list[dict[str, str]]:
    if not settings.printer_tcp_discovery_enabled or not settings.printer_snmp_subnets.strip():
        return []

    log = logger or logging.getLogger(__name__)
    targets = _iter_subnet_hosts(settings.printer_snmp_subnets, settings.printer_snmp_max_hosts, log)
    if not targets:
        return []

    max_workers = max(1, min(settings.printer_snmp_workers, len(targets)))
    log.info(
        "TCP printer discovery started targets=%s workers=%s ports=%s",
        len(targets),
        max_workers,
        settings.printer_tcp_ports,
    )

    rows: list[dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(_scan_tcp_printer_ip, ip_address, settings): ip_address for ip_address in targets}
        for index, future in enumerate(as_completed(future_map), start=1):
            ip_address = future_map[future]
            try:
                row = future.result()
            except Exception as exc:
                log.debug("TCP scan failed for %s: %s", ip_address, exc)
                continue
            if row:
                rows.append(row)
                log.info("TCP printer found ip=%s name=%s note=%s", row["ip_address"], row["name"], row["note"])
            if index % 256 == 0:
                log.info("TCP printer discovery progress: %s/%s found=%s", index, len(targets), len(rows))
    log.info("TCP printer discovery completed targets=%s found=%s", len(targets), len(rows))
    return rows


def load_printer_rows(path: str) -> list[dict[str, str]]:
    target = Path(path)
    if not target.exists():
        return []

    rows: list[dict[str, str]] = []
    with target.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        for row in reader:
            name = _clean(row.get("name") or row.get("printer") or row.get("hostname"))
            ip_address = _clean(row.get("ip") or row.get("ip_address"))
            location = _clean(row.get("location"))
            note = _clean(row.get("note"))
            if not name or not ip_address:
                continue
            rows.append({"name": name, "ip_address": ip_address, "location": location, "note": note, "source": "csv"})
    return rows


def _dedupe_printer_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    deduped: dict[str, dict[str, str]] = {}
    for row in rows:
        key = row["ip_address"]
        existing = deduped.get(key)
        existing_priority = SOURCE_PRIORITY.get(existing.get("source") if existing else "", 0)
        row_priority = SOURCE_PRIORITY.get(row.get("source") or "", 0)
        if existing is None or row_priority >= existing_priority:
            if existing is not None:
                row["location"] = row.get("location") or existing.get("location") or ""
                if existing.get("note") and row.get("note") and existing["note"] not in row["note"]:
                    row["note"] = f"{row['note']}; {existing['note']}"
                elif existing.get("note") and not row.get("note"):
                    row["note"] = existing["note"]
            deduped[key] = row
    return list(deduped.values())


def clear_printer_rows(db: Session) -> int:
    cleared = 0
    for machine in db.scalars(select(Machine).where(Machine.source_type == "printer")).all():
        db.delete(machine)
        cleared += 1
    db.flush()
    return cleared


def sync_printer_rows(
    db: Session,
    printer_rows: list[dict[str, str]],
    delete_missing: bool = False,
    clear_before_sync: bool = False,
) -> int:
    if clear_before_sync:
        clear_printer_rows(db)

    seen: set[str] = set()

    for row in _dedupe_printer_rows(printer_rows):
        normalized = _printer_key(row["name"], row["ip_address"])
        seen.add(normalized)
        machine = db.scalar(select(Machine).where(Machine.normalized_hostname == normalized))
        if machine is None:
            existing_by_ip = db.scalar(
                select(Machine).where(Machine.source_type == "printer", Machine.ip_address == row["ip_address"])
            )
            machine = existing_by_ip or Machine(hostname=row["name"], normalized_hostname=normalized)
            if existing_by_ip is None:
                db.add(machine)

        machine.hostname = row["name"]
        machine.normalized_hostname = normalized
        machine.source_type = "printer"
        machine.source_ou = None
        machine.computer_dn = None
        machine.object_guid = None
        machine.dns_hostname = None
        machine.ad_user_dn = None
        machine.ad_user_sam = None
        machine.manual_user_key = None
        machine.full_name = None
        machine.position_title = None
        machine.department = None
        machine.company = None
        machine.works_on = "Принтер"
        machine.ip_address = row["ip_address"]
        machine.location = row["location"] or machine.location
        machine.note = row["note"] or machine.note
        machine.match_status = "printer"
        machine.match_score = 100
        machine.match_note = f"printer from {row.get('source') or 'discovery'}"
        machine.is_active = True

    if delete_missing and seen and not clear_before_sync:
        for machine in db.scalars(select(Machine).where(Machine.source_type == "printer")).all():
            if machine.normalized_hostname not in seen:
                db.delete(machine)

    return len(seen)


def sync_printers(db: Session, settings: Settings, logger: logging.Logger | None = None) -> int:
    rows = load_printer_rows(settings.printers_file)
    rows.extend(discover_snmp_printers(settings, logger))
    rows.extend(discover_tcp_printers(settings, logger))
    rows.extend(discover_http_printers(settings, logger))
    return sync_printer_rows(db, rows, settings.printers_delete_missing, settings.printer_clear_before_sync)
