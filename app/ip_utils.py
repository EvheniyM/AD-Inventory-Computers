import ipaddress
import re


def _iter_network_specs(value: str | None):
    for raw in re.split(r"[\s,;]+", value or ""):
        spec = raw.strip()
        if spec:
            yield spec


def ip_in_configured_ranges(ip_address: str | None, ranges: str | None) -> bool:
    if not ip_address or not ranges:
        return False
    addresses = []
    for part in re.split(r"[\s,;/]+", ip_address.strip()):
        if not part:
            continue
        try:
            addresses.append(ipaddress.ip_address(part))
        except ValueError:
            continue
    if not addresses:
        return False

    for spec in _iter_network_specs(ranges):
        try:
            if "-" in spec and "/" not in spec:
                start_raw, end_raw = spec.split("-", 1)
                start = ipaddress.ip_address(start_raw.strip())
                end = ipaddress.ip_address(end_raw.strip())
                if any(start <= address <= end for address in addresses):
                    return True
            else:
                network = ipaddress.ip_network(spec, strict=False)
                if any(address in network for address in addresses):
                    return True
        except ValueError:
            continue
    return False
