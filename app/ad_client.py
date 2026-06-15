import logging
import re
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

from ldap3 import ALL, BASE, LEVEL, SUBTREE, Connection, Server, Tls
from ldap3.utils.conv import escape_filter_chars

from app.config import Settings


logger = logging.getLogger(__name__)

COMPUTER_ATTRIBUTES = [
    "cn",
    "name",
    "dNSHostName",
    "objectGUID",
    "distinguishedName",
    "whenChanged",
    "operatingSystem",
    "memberOf",
]

BASE_USER_ATTRIBUTES = [
    "cn",
    "name",
    "sAMAccountName",
    "userPrincipalName",
    "mail",
    "displayName",
    "givenName",
    "initials",
    "sn",
    "title",
    "department",
    "company",
    "distinguishedName",
    "employeeID",
    "physicalDeliveryOfficeName",
]

OPTIONAL_USER_ATTRIBUTES = [
    "mailNickname",
    "proxyAddresses",
    "otherMailbox",
]

USER_ATTRIBUTES = BASE_USER_ATTRIBUTES + OPTIONAL_USER_ATTRIBUTES

MULTI_VALUE_ATTRIBUTES = {"proxyAddresses", "otherMailbox", "memberOf", "member"}
INVALID_ATTRIBUTE_RE = re.compile(r"invalid attribute type\s+([A-Za-z0-9_-]+)", re.IGNORECASE)


def _first(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _clean_entry(item: dict[str, Any]) -> dict[str, Any]:
    attrs = item.get("attributes", {})
    cleaned = {
        key: value if key in MULTI_VALUE_ATTRIBUTES else _first(value)
        for key, value in attrs.items()
    }
    cleaned["distinguishedName"] = cleaned.get("distinguishedName") or item.get("dn")
    return cleaned


def _scope(value: str):
    return LEVEL if value.upper() == "LEVEL" else SUBTREE


class ActiveDirectoryClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.connection: Connection | None = None

    def __enter__(self) -> "ActiveDirectoryClient":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.connection:
            self.connection.unbind()

    def connect(self) -> None:
        if not self.settings.ad_server:
            raise RuntimeError("AD_SERVER is empty")
        server_name, port, use_ssl = self._parse_server()
        if self.settings.ad_require_ldaps and not use_ssl:
            raise RuntimeError("LDAPS is required: use AD_SERVER=ldaps://domain-controller:636")

        tls = None
        if use_ssl:
            validate = ssl.CERT_REQUIRED if self.settings.ad_validate_cert else ssl.CERT_NONE
            if self.settings.ad_allow_insecure_tls:
                validate = ssl.CERT_NONE
            tls = Tls(
                validate=validate,
                ca_certs_file=self.settings.ad_ca_cert_file or None,
            )
        server = Server(server_name, port=port, use_ssl=use_ssl, get_info=ALL, tls=tls)
        self.connection = Connection(
            server,
            user=self.settings.ad_user,
            password=self.settings.ad_password,
            auto_bind=True,
            receive_timeout=30,
        )

    def _parse_server(self) -> tuple[str, int | None, bool]:
        raw = self.settings.ad_server
        if "://" not in raw:
            return raw, None, self.settings.ad_use_ssl
        parsed = urlparse(raw)
        return parsed.hostname or raw, parsed.port, parsed.scheme.lower() == "ldaps"

    def _paged_search(self, base_dn: str, ldap_filter: str, attributes: list[str], search_scope) -> list[dict[str, Any]]:
        if not self.connection:
            raise RuntimeError("AD connection is not open")
        rows: list[dict[str, Any]] = []
        for item in self.connection.extend.standard.paged_search(
            search_base=base_dn,
            search_filter=ldap_filter,
            search_scope=search_scope,
            attributes=attributes,
            paged_size=500,
            generator=True,
        ):
            if item.get("type") == "searchResEntry":
                rows.append(_clean_entry(item))
        return rows

    def load_computers(self) -> list[dict[str, Any]]:
        computer_filter = "(&(objectCategory=computer)(objectClass=computer))"
        physical = self._paged_search(
            self.settings.ad_computer_physical_base_dn,
            computer_filter,
            COMPUTER_ATTRIBUTES,
            _scope(self.settings.ad_physical_search_scope),
        )
        for row in physical:
            row["source_type"] = "physical"
            row["source_ou"] = self.settings.ad_computer_physical_base_dn

        virtual = self._paged_search(
            self.settings.ad_computer_virtual_base_dn,
            computer_filter,
            COMPUTER_ATTRIBUTES,
            _scope(self.settings.ad_virtual_search_scope),
        )
        for row in virtual:
            row["source_type"] = "virtual"
            row["source_ou"] = self.settings.ad_computer_virtual_base_dn

        deduped: dict[str, dict[str, Any]] = {}
        for row in physical + virtual:
            key = str(row.get("objectGUID") or row.get("distinguishedName") or row.get("name")).lower()
            if row["source_type"] == "virtual" or key not in deduped:
                deduped[key] = row
        return list(deduped.values())

    def load_group_members(self, group_dn: str) -> list[str]:
        if not group_dn:
            return []
        rows = self._paged_search(group_dn, "(objectClass=group)", ["member"], BASE)
        if not rows:
            return []
        members = rows[0].get("member") or []
        if not isinstance(members, list):
            members = [members]
        return [str(member) for member in members if str(member).strip()]

    def load_computer_dns_in_group(self, group_dn: str) -> list[str]:
        if not group_dn:
            return []
        group_filter = (
            "(&(objectCategory=computer)(objectClass=computer)"
            f"(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(group_dn)}))"
        )
        rows: list[dict[str, Any]] = []
        search_roots = [
            (self.settings.ad_computer_physical_base_dn, _scope(self.settings.ad_physical_search_scope)),
            (self.settings.ad_computer_virtual_base_dn, _scope(self.settings.ad_virtual_search_scope)),
            (self.settings.ad_user_base_dn, SUBTREE),
        ]
        searched: set[tuple[str, Any]] = set()
        for base_dn, search_scope in search_roots:
            key = (base_dn.lower(), str(search_scope))
            if not base_dn or key in searched:
                continue
            searched.add(key)
            rows.extend(self._paged_search(base_dn, group_filter, ["distinguishedName"], search_scope))
        dns = {
            str(row.get("distinguishedName") or "").strip()
            for row in rows
            if str(row.get("distinguishedName") or "").strip()
        }
        return sorted(dns)

    def load_matching_group_member_dns(self, group_dn: str, candidate_dns: list[str]) -> list[str]:
        if not group_dn or not candidate_dns:
            return []
        matched: set[str] = set()
        for candidate_dn in sorted({str(item or "").strip() for item in candidate_dns if str(item or "").strip()}):
            member_filter = (
                "(&(objectClass=group)"
                f"(member:1.2.840.113556.1.4.1941:={escape_filter_chars(candidate_dn)}))"
            )
            rows = self._paged_search(group_dn, member_filter, ["distinguishedName"], BASE)
            if rows:
                matched.add(candidate_dn)
        return sorted(matched)

    def load_users(self) -> list[dict[str, Any]]:
        user_filter = (
            "(&(objectCategory=person)(objectClass=user)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        attributes = list(USER_ATTRIBUTES)
        skipped: list[str] = []
        while True:
            try:
                rows = self._paged_search(self.settings.ad_user_base_dn, user_filter, attributes, SUBTREE)
                if skipped:
                    logger.warning("Skipped unsupported AD user attributes: %s", ", ".join(skipped))
                return rows
            except Exception as exc:
                message = str(exc)
                match = INVALID_ATTRIBUTE_RE.search(message)
                if not match:
                    raise
                invalid_attribute = match.group(1)
                if invalid_attribute not in attributes:
                    raise
                attributes.remove(invalid_attribute)
                skipped.append(invalid_attribute)
                if not attributes:
                    raise RuntimeError("No valid AD user attributes left after LDAP schema fallback") from exc


def resolve_ip(hostname: str | None, dns_hostname: str | None, timeout_seconds: float = 1.5) -> str | None:
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        dns = None
    else:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout_seconds
        resolver.lifetime = timeout_seconds
        for candidate in (dns_hostname, hostname):
            if not candidate:
                continue
            try:
                answer = resolver.resolve(str(candidate), "A", lifetime=timeout_seconds)
                for record in answer:
                    return record.to_text()
            except (dns.exception.DNSException, OSError):
                continue

    for candidate in (dns_hostname, hostname):
        if not candidate:
            continue
        try:
            socket.setdefaulttimeout(timeout_seconds)
            return socket.gethostbyname(str(candidate))
        except OSError:
            continue
    return None
