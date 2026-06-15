import datetime as dt
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ad_client import ActiveDirectoryClient, resolve_ip
from app.config import get_settings
from app.excel_service import maybe_write_export
from app.ip_utils import ip_in_configured_ranges
from app.matcher import (
    UserMatch,
    find_best_user,
    hostname_tokens,
    normalize_hostname,
    normalize_text,
    token_match_score,
    token_prefix_match,
)
from app.models import Machine, SyncEvent
from app.network_device_service import NETWORK_SOURCE_TYPES, sync_network_devices
from app.printer_service import sync_printers


logger = logging.getLogger(__name__)

CHECKPOINT_VPN_GROUP = "checkpoint_vpn"
CHECKPOINT_FIREWALL_GROUP = "checkpoint_firewall"


def _display_name(user: dict[str, Any]) -> str | None:
    return user.get("displayName") or user.get("cn") or user.get("sAMAccountName")


def _default_works_on(source_type: str) -> str:
    return "VM" if source_type == "virtual" else "ПК"


def _short_dns_hostname(value: Any) -> str | None:
    cleaned = _clean(value)
    if not cleaned:
        return None
    return cleaned.split(".", 1)[0].strip() or None


def _computer_hostname(computer: dict[str, Any]) -> str | None:
    hostname = _short_dns_hostname(computer.get("dNSHostName"))
    if hostname:
        return hostname.upper()
    hostname = _clean(computer.get("name") or computer.get("cn"))
    return hostname.upper() if hostname else None


def _computer_guid(computer: dict[str, Any]) -> str | None:
    value = _clean(computer.get("objectGUID"))
    return value.lower() if value else None


def _works_on(source_type: str, ip_address: str | None, wifi_networks: str | None) -> str:
    if _has_wifi_ip(ip_address, wifi_networks):
        return "Ноутбук"
    return _default_works_on(source_type)


def _has_wifi_ip(ip_address: str | None, wifi_networks: str | None) -> bool:
    return ip_in_configured_ranges(ip_address, wifi_networks)


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _ad_group_names(value: Any) -> set[str]:
    if not value:
        return set()
    raw_values = value if isinstance(value, list) else [value]
    names: set[str] = set()
    for raw in raw_values:
        text = str(raw).strip()
        if not text:
            continue
        first_part = text.split(",", 1)[0]
        if first_part.lower().startswith("cn="):
            text = first_part[3:]
        names.add(normalize_text(text).replace("-", "_"))
    return names


def _checkpoint_oschad_access(computer: dict[str, Any]) -> str | None:
    group_names = _ad_group_names(computer.get("memberOf"))
    if CHECKPOINT_VPN_GROUP in group_names:
        return "Да"
    if CHECKPOINT_FIREWALL_GROUP in group_names:
        return "Нет"
    return None


def _normalize_dn(value: Any) -> str:
    return re.sub(r"\s+", "", str(value or "")).lower()


def _checkpoint_oschad_access_by_group_members(
    computer: dict[str, Any],
    vpn_member_dns: set[str],
    firewall_member_dns: set[str],
) -> str | None:
    computer_dn = _normalize_dn(computer.get("distinguishedName"))
    if not computer_dn:
        return None
    if computer_dn in vpn_member_dns:
        return "Да"
    if computer_dn in firewall_member_dns:
        return "Нет"
    return None


def _load_group_member_dns(ad: ActiveDirectoryClient, group_dn: str, label: str) -> set[str]:
    if not group_dn:
        return set()
    member_dns: set[str] = set()
    try:
        member_dns.update(_normalize_dn(member) for member in ad.load_group_members(group_dn))
    except Exception as exc:
        logger.warning("Could not load %s group members from AD: %s", label, exc)
    try:
        matched_dns = {_normalize_dn(member) for member in ad.load_computer_dns_in_group(group_dn)}
        if matched_dns:
            logger.info("%s computers matched by AD memberOf rule: %s", label, len(matched_dns))
        member_dns.update(matched_dns)
    except Exception as exc:
        logger.warning("Could not search %s computer membership in AD: %s", label, exc)
    return {member for member in member_dns if member}


def _load_matching_group_member_dns(
    ad: ActiveDirectoryClient,
    group_dn: str,
    label: str,
    candidate_dns: list[str],
) -> set[str]:
    if not group_dn or not candidate_dns:
        return set()
    try:
        matched_dns = {_normalize_dn(member) for member in ad.load_matching_group_member_dns(group_dn, candidate_dns)}
        if matched_dns:
            logger.info("%s computers matched by reverse AD member rule: %s", label, len(matched_dns))
        return {member for member in matched_dns if member}
    except Exception as exc:
        logger.warning("Could not reverse-search %s computer membership in AD: %s", label, exc)
        return set()


def _assign_if_value(machine: Machine, attr: str, value: Any) -> None:
    cleaned = _clean(value)
    if cleaned:
        setattr(machine, attr, cleaned)


def _user_key_values(user: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for key in (
        "sAMAccountName",
        "mailNickname",
        "displayName",
        "mail",
        "userPrincipalName",
        "proxyAddresses",
        "otherMailbox",
    ):
        value = user.get(key)
        if not value:
            continue
        raw_values = value if isinstance(value, list) else [value]
        for raw in raw_values:
            text = str(raw)
            if ":" in text and text.split(":", 1)[0].lower() in {"smtp", "sip", "x400", "x500"}:
                text = text.split(":", 1)[1]
            values.add(normalize_text(text))
            if "@" in text:
                values.add(normalize_text(text.split("@", 1)[0]))
    return {value for value in values if value}


def find_manual_user(manual_user_key: str | None, users: list[dict[str, Any]]) -> UserMatch | None:
    if not manual_user_key:
        return None
    wanted = normalize_text(manual_user_key)
    if not wanted:
        return None
    exact = [user for user in users if wanted in _user_key_values(user)]
    if len(exact) == 1:
        user = exact[0]
        name = user.get("displayName") or user.get("sAMAccountName")
        return UserMatch(user, "manual", 100, f"manual AD override matched to {name}")
    if len(exact) > 1:
        names = ", ".join(str(user.get("displayName") or user.get("sAMAccountName")) for user in exact[:3])
        return UserMatch(None, "manual_ambiguous", 100, f"manual AD override matched several users: {names}")
    return UserMatch(None, "manual_not_found", 0, f"manual AD override not found: {manual_user_key}")


def apply_user_details(machine: Machine, user: dict[str, Any]) -> None:
    machine.ad_user_dn = user.get("distinguishedName")
    machine.ad_user_sam = user.get("sAMAccountName")
    _assign_if_value(machine, "full_name", _display_name(user))
    _assign_if_value(machine, "position_title", user.get("title"))
    _assign_if_value(machine, "department", user.get("department"))
    _assign_if_value(machine, "company", user.get("company"))
    if not machine.location:
        _assign_if_value(machine, "location", user.get("physicalDeliveryOfficeName"))


def _copy_related_user_details(target: Machine, source: Machine) -> None:
    target.ad_user_dn = source.ad_user_dn
    target.ad_user_sam = source.ad_user_sam
    target.full_name = source.full_name
    target.position_title = source.position_title
    target.department = source.department
    target.company = source.company
    if not target.location:
        target.location = source.location
    target.match_status = "matched"
    target.match_score = max(target.match_score or 0, 100)
    target.match_note = f"matched via related hostname {source.hostname}"


def _related_hostname_tokens(machine: Machine) -> list[str]:
    tokens = hostname_tokens(machine.hostname, machine.source_type)
    if len(tokens) < 2:
        return []
    return tokens[:2]


def _related_hostname_key(machine: Machine) -> str:
    tokens = _related_hostname_tokens(machine)
    return "-".join(tokens) if tokens else ""


def _related_hostname_matches(source: Machine, candidate: Machine) -> bool:
    source_tokens = _related_hostname_tokens(source)
    candidate_tokens = _related_hostname_tokens(candidate)
    if len(source_tokens) < 2 or len(candidate_tokens) < 2:
        return False
    first_score = token_match_score(source_tokens[0], candidate_tokens[0])
    return first_score >= 90 and token_prefix_match(source_tokens[1], candidate_tokens[1])


def apply_related_hostname_matches(db: Session) -> int:
    machines = list(db.scalars(select(Machine)).all())
    matched = [
        machine
        for machine in machines
        if machine.ad_user_sam and machine.match_status in {"matched", "manual"} and _related_hostname_key(machine)
    ]
    fixed = 0
    for machine in machines:
        if machine.ad_user_sam or machine.match_status not in {"ambiguous", "not_found", "not_enough_hostname_tokens"}:
            continue
        key = _related_hostname_key(machine)
        if len(key) < 4:
            continue
        related = [candidate for candidate in matched if candidate.id != machine.id and _related_hostname_matches(machine, candidate)]
        user_ids = {candidate.ad_user_sam.lower() for candidate in related if candidate.ad_user_sam}
        if len(user_ids) != 1:
            continue
        _copy_related_user_details(machine, related[0])
        fixed += 1
    return fixed


def resolve_computer_ips(computers: list[dict[str, Any]], timeout_seconds: float, workers: int) -> dict[str, str]:
    candidates: dict[str, tuple[str, str | None]] = {}
    for computer in computers:
        hostname = _computer_hostname(computer)
        normalized = normalize_hostname(hostname)
        if not normalized:
            continue
        candidates[normalized] = (hostname or "", _clean(computer.get("dNSHostName")))

    if not candidates:
        return {}

    ip_by_normalized: dict[str, str] = {}
    max_workers = max(1, min(workers, len(candidates)))
    logger.info("Resolving DNS for %s computers with %s workers", len(candidates), max_workers)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(resolve_ip, hostname, dns_hostname, timeout_seconds): normalized
            for normalized, (hostname, dns_hostname) in candidates.items()
        }
        for index, future in enumerate(as_completed(future_map), start=1):
            normalized = future_map[future]
            try:
                ip_address = future.result()
            except Exception as exc:
                logger.debug("DNS resolve failed for %s: %s", normalized, exc)
                continue
            if ip_address:
                ip_by_normalized[normalized] = ip_address
            if index % 100 == 0:
                logger.info("Resolved DNS: %s/%s", index, len(future_map))
    logger.info("DNS resolved %s/%s computers", len(ip_by_normalized), len(candidates))
    return ip_by_normalized


def _sync_discovery(db: Session, settings) -> None:
    try:
        printer_count = sync_printers(db, settings, logger)
        if printer_count:
            logger.info("Synced printers: %s", printer_count)
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.warning("Printer sync failed, continuing AD sync: %s", exc)

    try:
        network_device_count = sync_network_devices(db, settings, logger)
        if network_device_count:
            logger.info("Synced network devices: %s", network_device_count)
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.warning("Network device sync failed, continuing AD sync: %s", exc)


def run_sync(db: Session, include_discovery: bool = True) -> SyncEvent:
    settings = get_settings()
    event = SyncEvent(started_at=dt.datetime.now(dt.timezone.utc), status="running")
    db.add(event)
    db.commit()
    db.refresh(event)

    created = 0
    updated = 0
    deleted = 0
    now = dt.datetime.now(dt.timezone.utc)

    try:
        with ActiveDirectoryClient(settings) as ad:
            computers = ad.load_computers()
            computer_dns = [_clean(computer.get("distinguishedName")) for computer in computers]
            computer_dns = [computer_dn for computer_dn in computer_dns if computer_dn]
            vpn_member_dns = _load_group_member_dns(ad, settings.checkpoint_vpn_group_dn, "CheckPoint VPN")
            firewall_member_dns = _load_group_member_dns(ad, settings.checkpoint_firewall_group_dn, "CheckPoint Firewall")
            vpn_member_dns.update(
                _load_matching_group_member_dns(ad, settings.checkpoint_vpn_group_dn, "CheckPoint VPN", computer_dns)
            )
            firewall_member_dns.update(
                _load_matching_group_member_dns(
                    ad,
                    settings.checkpoint_firewall_group_dn,
                    "CheckPoint Firewall",
                    computer_dns,
                )
            )
            users = ad.load_users()

        logger.info("AD loaded computers=%s users=%s", len(computers), len(users))
        logger.info(
            "CheckPoint group members loaded vpn=%s firewall=%s",
            len(vpn_member_dns),
            len(firewall_member_dns),
        )

        if not computers:
            raise RuntimeError("AD returned 0 computers from target OUs; refusing to delete existing inventory rows")

        ip_by_normalized: dict[str, str] = {}
        if settings.dns_resolve_ip:
            ip_by_normalized = resolve_computer_ips(
                computers,
                settings.dns_query_timeout_seconds,
                settings.dns_resolve_workers,
            )

        seen_normalized: set[str] = set()
        seen_guids: set[str] = set()
        for index, computer in enumerate(computers, start=1):
            if index == 1 or index % 50 == 0:
                logger.info("Processing AD computers: %s/%s", index, len(computers))
            hostname = _computer_hostname(computer)
            if not hostname:
                continue
            normalized = normalize_hostname(hostname)
            if not normalized:
                continue
            seen_normalized.add(normalized)
            object_guid = _computer_guid(computer)
            if object_guid:
                seen_guids.add(object_guid)

            machine = None
            if object_guid:
                machine = db.scalar(select(Machine).where(func.lower(Machine.object_guid) == object_guid))
            existing_by_hostname = db.scalar(select(Machine).where(Machine.normalized_hostname == normalized))
            legacy_hostname = _clean(computer.get("name") or computer.get("cn"))
            legacy_normalized = normalize_hostname(legacy_hostname)
            existing_by_legacy_hostname = None
            if legacy_normalized and legacy_normalized != normalized:
                existing_by_legacy_hostname = db.scalar(
                    select(Machine).where(Machine.normalized_hostname == legacy_normalized)
                )
            if machine is None:
                machine = existing_by_hostname or existing_by_legacy_hostname
            elif existing_by_hostname is not None and existing_by_hostname.id != machine.id:
                db.delete(existing_by_hostname)
                db.flush()
            if machine is not None and existing_by_legacy_hostname is not None and existing_by_legacy_hostname.id != machine.id:
                db.delete(existing_by_legacy_hostname)
                db.flush()
            if machine is None:
                machine = Machine(hostname=hostname, normalized_hostname=normalized)
                db.add(machine)
                created += 1
            else:
                updated += 1

            source_type = computer.get("source_type") or "physical"
            dns_hostname = computer.get("dNSHostName")
            machine.hostname = hostname
            machine.normalized_hostname = normalized
            machine.source_type = source_type
            machine.source_ou = computer.get("source_ou")
            machine.computer_dn = computer.get("distinguishedName")
            machine.object_guid = object_guid or machine.object_guid
            machine.dns_hostname = dns_hostname
            machine.is_active = True
            machine.last_seen_at = now
            machine.last_synced_at = now

            if settings.dns_resolve_ip:
                ip_address = ip_by_normalized.get(normalized)
                if ip_address:
                    machine.ip_address = ip_address
            machine.works_on = _works_on(source_type, machine.ip_address, settings.wifi_networks)
            checkpoint_access = _checkpoint_oschad_access_by_group_members(
                computer,
                vpn_member_dns,
                firewall_member_dns,
            ) or _checkpoint_oschad_access(computer)
            if checkpoint_access:
                machine.oschad_access = checkpoint_access

            manual_match = find_manual_user(machine.manual_user_key, users)
            match = manual_match if manual_match is not None else find_best_user(hostname, source_type, users)
            machine.match_status = match.status
            machine.match_score = match.score
            machine.match_note = match.note
            if match.user:
                apply_user_details(machine, match.user)

        db.flush()
        related_fixed = apply_related_hostname_matches(db)
        if related_fixed:
            logger.info("Matched %s computers via related hostname prefixes", related_fixed)

        for machine in db.scalars(select(Machine)).all():
            if machine.source_type == "printer" or machine.source_type in NETWORK_SOURCE_TYPES:
                continue
            known_by_guid = bool(machine.object_guid and machine.object_guid.lower() in seen_guids)
            known_by_hostname = machine.normalized_hostname in seen_normalized
            if known_by_guid or known_by_hostname:
                continue
            if settings.delete_missing_computers:
                db.delete(machine)
                deleted += 1
            elif machine.is_active:
                machine.is_active = False
                machine.last_synced_at = now
                deleted += 1

        event.status = "success"
        event.finished_at = dt.datetime.now(dt.timezone.utc)
        event.seen_computers = len(seen_normalized)
        event.created_rows = created
        event.updated_rows = updated
        event.deleted_rows = deleted
        event.message = "sync completed"
        db.commit()
        logger.info(
            "AD sync completed seen=%s created=%s updated=%s deleted=%s",
            len(seen_normalized),
            created,
            updated,
            deleted,
        )
        maybe_write_export(db)
        if include_discovery:
            _sync_discovery(db, settings)
            maybe_write_export(db)
        return event

    except Exception as exc:
        db.rollback()
        failed = db.get(SyncEvent, event.id)
        if failed:
            failed.status = "failed"
            failed.finished_at = dt.datetime.now(dt.timezone.utc)
            failed.message = str(exc)
            db.commit()
            return failed
        raise
