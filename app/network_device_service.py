from __future__ import annotations

import ipaddress
import logging
import re
import socket
import ssl
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import unescape
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.matcher import normalize_hostname
from app.models import Machine
from app.printer_service import SYS_DESCR, SYS_LOCATION, SYS_NAME, snmp_get


HTML_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
IP_ADDRESS_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
LAST_OCTET_RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")
JS_CONCAT_RE = re.compile(r"['\"]?\s*\+\s*[A-Za-z0-9_]+\s*\+\s*['\"]?")
BAD_NAME_TOKENS = (
    "id_vc_welcome",
    "id_esx_welcome",
    "javascript",
    "document.",
    "window.",
    "function(",
    "{",
    "}",
)
BAD_TITLES = {
    "home",
    "login",
    "login:",
    "password",
    "password:",
    "status",
    "username",
    "username:",
    "welcome",
    "remote ui",
    "web ui",
    "localhost",
    "localhost.localdomain",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
}
NAS_NAME_RE = re.compile(r"\b(?P<name>(?:TrueNAS|FreeNAS)(?:[-\s](?:SCALE|CORE))?)\b", re.IGNORECASE)
NETWORK_SOURCE_TYPES = {"switch", "server", "wifi", "network"}
DEVICE_LABELS = {
    "switch": "Свич",
    "server": "Сервер",
    "wifi": "Wi-Fi",
    "network": "Мережевий пристрій",
}
SWITCH_KEYWORDS = (
    "switch",
    "catalyst",
    "procurve",
    "arubaos-switch",
    "edgeswitch",
    "d-link",
    "dlink",
    "tp-link",
    "tplink",
    "zyxel",
    "netgear",
    "huawei s",
    "hpe officeconnect",
    "mikrotik routeros",
    "routerboard",
)
WIFI_KEYWORDS = (
    "access point",
    "wireless",
    "wi-fi",
    "wifi",
    "aironet",
    "unifi",
    "ubiquiti",
    "aruba ap",
    "meraki",
    "omada",
    "eap",
    "cap ac",
    "wlan",
)
SERVER_KEYWORDS = (
    "windows server",
    "server",
    "vmware",
    "vcenter",
    "vcentre",
    "vsphere",
    "esxi",
    "vmware esxi",
    "hyper-v",
    "ubuntu",
    "debian",
    "centos",
    "red hat",
    "linux",
    "freenas",
    "truenas",
    "nas",
    "proliant",
    "poweredge",
    "system x",
    "thinksystem",
)


def _clean(value: Any) -> str:
    text = str(value or "")
    text = text.replace("\x00", "")
    text = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _split_csv(value: str) -> list[str]:
    return [item.strip().lower() for item in value.split(",") if item.strip()]


def _split_csv_int(value: str) -> list[int]:
    ports: list[int] = []
    for raw in value.split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            port = int(raw)
        except ValueError:
            continue
        if 0 < port <= 65535:
            ports.append(port)
    return ports


def _strip_ip(value: str) -> str:
    cleaned = IP_ADDRESS_RE.sub("", _clean(value).replace("\xa0", " "))
    cleaned = JS_CONCAT_RE.sub(" ", cleaned)
    cleaned = re.sub(r"[\"'`]+", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip(" -:：|;,\t\r\n")


def _short_description(value: str) -> str:
    cleaned = _strip_ip(unescape(re.sub(r"<[^>]+>", " ", _clean(value))))
    for separator in (";", ". Hardware:", " Hardware:", " SN:", " Serial", " Firmware", " Version", "\n"):
        if separator in cleaned:
            cleaned = cleaned.split(separator, 1)[0].strip()
    return cleaned[:255]


def _network_key(ip_address: str) -> str:
    return f"network-{re.sub(r'[^0-9A-Za-z]+', '-', _clean(ip_address)).strip('-').lower()}"


def _iter_last_octet_range(value: str, logger: logging.Logger | None = None) -> list[str]:
    match = LAST_OCTET_RANGE_RE.match(value)
    if not match:
        return []
    prefix, start_raw, end_raw = match.groups()
    start = int(start_raw)
    end = int(end_raw)
    if not (0 <= start <= 255 and 0 <= end <= 255 and start <= end):
        if logger:
            logger.warning("Invalid network device IP range skipped: %s", value)
        return []
    return [f"{prefix}{last_octet}" for last_octet in range(start, end + 1)]


def _short_hostname(value: str) -> str:
    cleaned = _strip_ip(value)
    if not cleaned:
        return ""
    if "@" in cleaned:
        return ""
    cleaned = cleaned.split("/", 1)[0].strip()
    cleaned = cleaned.split(":", 1)[0].strip()
    if "." in cleaned:
        cleaned = cleaned.split(".", 1)[0].strip()
    return cleaned[:120]


def _is_bad_name(value: str, ip_address: str = "") -> bool:
    cleaned = _strip_ip(value)
    if not cleaned:
        return True
    lower = cleaned.lower()
    if ip_address and lower == ip_address.lower():
        return True
    if lower in BAD_TITLES:
        return True
    if lower.startswith(("localhost.", "localhost ")):
        return True
    if any(token in lower for token in BAD_NAME_TOKENS):
        return True
    if any(token in lower for token in ("username:", "password:", "user access verification")):
        return True
    if lower.startswith(("http ", "https ", "ssh-", "user access verification", "username", "password")):
        return True
    return False


def _name_from_description(value: str) -> str:
    text = _clean(unescape(re.sub(r"<[^>]+>", " ", value)))
    match = NAS_NAME_RE.search(text)
    if match:
        return match.group("name").replace("-", " ").strip()
    return _short_description(text)


def _iter_subnet_hosts(subnets: str, max_hosts: int, logger: logging.Logger | None = None) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for raw in subnets.split(","):
        value = raw.strip()
        if not value:
            continue
        range_hosts = _iter_last_octet_range(value, logger)
        if range_hosts:
            for ip_address in range_hosts:
                if ip_address in seen:
                    continue
                hosts.append(ip_address)
                seen.add(ip_address)
                if len(hosts) >= max_hosts:
                    return hosts
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            if logger:
                logger.warning("Invalid network device subnet/range skipped: %s (%s)", value, exc)
            continue
        for address in network.hosts():
            ip_address = str(address)
            if ip_address in seen:
                continue
            hosts.append(ip_address)
            seen.add(ip_address)
            if len(hosts) >= max_hosts:
                return hosts
    return hosts


def _snmp_value(ip_address: str, oid: str, settings: Settings) -> str:
    try:
        return _clean(
            snmp_get(
                ip_address,
                oid,
                settings.network_device_snmp_community,
                settings.network_device_snmp_port,
                settings.network_device_snmp_timeout_seconds,
                versions=(1, 0),
            )
            or ""
        )
    except (OSError, TimeoutError):
        return ""


def _http_title(ip_address: str, settings: Settings) -> str:
    if not settings.network_device_http_enabled:
        return ""
    context = ssl._create_unverified_context()
    for port in _split_csv_int(settings.network_device_http_ports):
        schemes = ("https", "http") if port in {443, 8443} else ("http",)
        for scheme in schemes:
            base_url = f"{scheme}://{ip_address}"
            if not (scheme == "http" and port == 80) and not (scheme == "https" and port == 443):
                base_url = f"{base_url}:{port}"
            try:
                request = Request(f"{base_url}/", headers={"User-Agent": "BARS-Inventory/1.0"})
                with urlopen(request, timeout=settings.network_device_http_timeout_seconds, context=context) as response:
                    body = response.read(65536).decode("utf-8", errors="replace")
            except (OSError, HTTPError, URLError, TimeoutError, ValueError):
                continue
            match = HTML_TITLE_RE.search(body)
            if match:
                title = _short_description(match.group(1))
                if title and not _is_bad_name(title, ip_address):
                    return title
    return ""


def _tls_certificate_name(ip_address: str, settings: Settings) -> str:
    if not settings.network_device_tls_name_enabled:
        return ""
    context = ssl._create_unverified_context()
    for port in _split_csv_int(settings.network_device_tls_ports):
        try:
            with socket.create_connection(
                (ip_address, port),
                timeout=settings.network_device_tls_timeout_seconds,
            ) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=ip_address) as tls_sock:
                    der = tls_sock.getpeercert(binary_form=True)
        except (OSError, TimeoutError, ssl.SSLError):
            continue
        if not der:
            continue
        try:
            pem = ssl.DER_cert_to_PEM_cert(der)
            with tempfile.NamedTemporaryFile("w+", suffix=".crt", delete=True) as cert_file:
                cert_file.write(pem)
                cert_file.flush()
                decoded = ssl._ssl._test_decode_cert(cert_file.name)
        except (OSError, ssl.SSLError, ValueError):
            continue

        names: list[str] = []
        for item in decoded.get("subjectAltName", ()):
            if len(item) == 2 and item[0].lower() == "dns":
                names.append(item[1])
        for subject_part in decoded.get("subject", ()):
            for key, value in subject_part:
                if key.lower() == "commonname":
                    names.append(value)

        for name in names:
            cleaned = _short_hostname(name)
            if cleaned and not _is_bad_name(cleaned, ip_address):
                return cleaned
    return ""


def _reverse_dns_name(ip_address: str, settings: Settings) -> str:
    if not settings.network_device_reverse_dns_enabled:
        return ""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
    except (OSError, socket.herror, socket.gaierror):
        return ""
    return _short_hostname(hostname)


def _tcp_port_open(ip_address: str, port: int, timeout_seconds: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout_seconds)
        try:
            return sock.connect_ex((ip_address, port)) == 0
        except OSError:
            return False


def _open_ports(ip_address: str, settings: Settings) -> list[int]:
    if not settings.network_device_tcp_discovery_enabled:
        return []
    return [
        port
        for port in _split_csv_int(settings.network_device_tcp_ports)
        if _tcp_port_open(ip_address, port, settings.network_device_tcp_timeout_seconds)
    ]


def _tcp_banner(ip_address: str, open_ports: list[int], settings: Settings) -> str:
    for port in (23, 22):
        if port not in open_ports:
            continue
        chunks: list[bytes] = []
        try:
            with socket.create_connection(
                (ip_address, port),
                timeout=settings.network_device_tcp_timeout_seconds,
            ) as sock:
                sock.settimeout(settings.network_device_tcp_timeout_seconds)
                for payload in (b"", b"\r\n"):
                    if payload:
                        sock.sendall(payload)
                    try:
                        data = sock.recv(2048)
                    except (OSError, TimeoutError):
                        data = b""
                    if data:
                        chunks.append(data)
        except (OSError, TimeoutError):
            continue
        banner = _short_description(b" ".join(chunks).decode("utf-8", errors="ignore"))
        if banner and not _is_bad_name(banner, ip_address):
            return banner
    return ""


def _contains_any(text: str, keywords: tuple[str, ...] | list[str]) -> bool:
    return any(keyword and keyword in text for keyword in keywords)


def _classify_device(text: str, open_ports: list[int]) -> str:
    lower = text.lower()
    if _contains_any(lower, WIFI_KEYWORDS):
        return "wifi"
    if _contains_any(lower, SWITCH_KEYWORDS):
        return "switch"
    if _contains_any(lower, SERVER_KEYWORDS):
        return "server"
    if any(port in {445, 3389, 5985, 5986} for port in open_ports):
        return "server"
    if 23 in open_ports:
        return "switch"
    return "network"


def _best_name(
    ip_address: str,
    sys_name: str,
    http_title: str,
    reverse_dns: str,
    tls_name: str,
    description: str,
    tcp_banner: str = "",
) -> str:
    description_name = _name_from_description(description)
    for value in (sys_name, reverse_dns, tls_name, http_title, tcp_banner, description_name):
        cleaned = _strip_ip(value)
        if cleaned and not _is_bad_name(cleaned, ip_address):
            return cleaned[:120]
    return f"Device {ip_address}"


def _scan_network_device_ip(ip_address: str, settings: Settings) -> dict[str, str] | None:
    sys_name = _snmp_value(ip_address, SYS_NAME, settings)
    description = _snmp_value(ip_address, SYS_DESCR, settings)
    location = _snmp_value(ip_address, SYS_LOCATION, settings)
    http_title = _http_title(ip_address, settings)
    reverse_dns = _reverse_dns_name(ip_address, settings)
    tls_name = _tls_certificate_name(ip_address, settings)
    open_ports = _open_ports(ip_address, settings)
    tcp_banner = _tcp_banner(ip_address, open_ports, settings)

    has_live_signal = any((sys_name, description, location, http_title, tls_name, tcp_banner, open_ports))
    if not has_live_signal:
        return None

    combined = _clean(f"{sys_name} {description} {location} {http_title} {reverse_dns} {tls_name} {tcp_banner}").lower()
    if _contains_any(combined, _split_csv(settings.network_device_exclude_keywords)):
        return None

    source_type = _classify_device(combined, open_ports)
    name = _best_name(ip_address, sys_name, http_title, reverse_dns, tls_name, description, tcp_banner)
    if not settings.network_device_include_unnamed and name == f"Device {ip_address}":
        return None
    short_description = _short_description(description or http_title or tcp_banner)
    note_parts = []
    if sys_name:
        note_parts.append(f"SNMP sysName={_clean(sys_name)}")
    if description:
        note_parts.append(f"SNMP sysDescr={_clean(description)[:180]}")
    if http_title:
        note_parts.append(f"HTTP title={_clean(http_title)}")
    if reverse_dns:
        note_parts.append(f"DNS={_clean(reverse_dns)}")
    if tls_name:
        note_parts.append(f"TLS name={_clean(tls_name)}")
    if tcp_banner:
        note_parts.append(f"TCP banner={_clean(tcp_banner)}")
    if open_ports:
        note_parts.append(f"TCP open ports={','.join(str(port) for port in open_ports)}")

    return {
        "hostname": _clean(name),
        "source_type": source_type,
        "works_on": DEVICE_LABELS[source_type],
        "ip_address": ip_address,
        "description": _clean(short_description),
        "location": _clean(location),
        "note": _clean("; ".join(note_parts)),
    }


def discover_network_devices(settings: Settings, logger: logging.Logger | None = None) -> list[dict[str, str]]:
    if not settings.network_device_discovery_enabled or not settings.network_device_subnets.strip():
        return []

    log = logger or logging.getLogger(__name__)
    targets = _iter_subnet_hosts(settings.network_device_subnets, settings.network_device_max_hosts, log)
    if not targets:
        return []

    max_workers = max(1, min(settings.network_device_workers, len(targets)))
    log.info("Network device discovery started targets=%s workers=%s", len(targets), max_workers)

    rows: list[dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(_scan_network_device_ip, ip_address, settings): ip_address for ip_address in targets}
        for index, future in enumerate(as_completed(future_map), start=1):
            ip_address = future_map[future]
            try:
                row = future.result()
            except Exception as exc:
                log.debug("Network device scan failed for %s: %s", ip_address, exc)
                continue
            if row:
                rows.append(row)
                log.info(
                    "Network device found ip=%s type=%s name=%s",
                    row["ip_address"],
                    row["works_on"],
                    row["hostname"],
                )
            if index % 256 == 0:
                log.info("Network device discovery progress: %s/%s found=%s", index, len(targets), len(rows))
    log.info("Network device discovery completed targets=%s found=%s", len(targets), len(rows))
    return rows


def clear_network_device_rows(db: Session) -> int:
    cleared = 0
    for machine in db.scalars(select(Machine).where(Machine.source_type.in_(NETWORK_SOURCE_TYPES))).all():
        db.delete(machine)
        cleared += 1
    db.flush()
    return cleared


def sync_network_device_rows(
    db: Session,
    rows: list[dict[str, str]],
    delete_missing: bool = False,
    clear_before_sync: bool = False,
) -> int:
    if clear_before_sync:
        clear_network_device_rows(db)

    seen: set[str] = set()
    for row in rows:
        normalized = _network_key(row["ip_address"])
        seen.add(normalized)
        machine = db.scalar(select(Machine).where(Machine.normalized_hostname == normalized))
        if machine is None:
            machine = db.scalar(
                select(Machine).where(Machine.source_type.in_(NETWORK_SOURCE_TYPES), Machine.ip_address == row["ip_address"])
            )
        if machine is None:
            machine = Machine(hostname=row["hostname"], normalized_hostname=normalized)
            db.add(machine)

        machine.hostname = row["hostname"]
        machine.normalized_hostname = normalized
        machine.source_type = row["source_type"]
        machine.source_ou = None
        machine.computer_dn = None
        machine.object_guid = None
        machine.dns_hostname = None
        machine.ad_user_dn = None
        machine.ad_user_sam = None
        machine.manual_user_key = None
        machine.full_name = row["description"] or None
        machine.position_title = None
        machine.department = None
        machine.company = None
        machine.works_on = row["works_on"]
        machine.ip_address = row["ip_address"]
        machine.location = row["location"] or machine.location
        machine.note = row["note"] or machine.note
        machine.match_status = "network"
        machine.match_score = 100
        machine.match_note = f"network discovery: {row['works_on']}"
        machine.is_active = True

    if delete_missing and seen and not clear_before_sync:
        for machine in db.scalars(select(Machine).where(Machine.source_type.in_(NETWORK_SOURCE_TYPES))).all():
            if machine.normalized_hostname not in seen:
                db.delete(machine)

    return len(seen)


def sync_network_devices(db: Session, settings: Settings, logger: logging.Logger | None = None) -> int:
    rows = discover_network_devices(settings, logger)
    return sync_network_device_rows(
        db,
        rows,
        settings.network_device_delete_missing,
        settings.network_device_clear_before_sync,
    )
