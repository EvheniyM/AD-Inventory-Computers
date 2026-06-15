import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any

from unidecode import unidecode


CYRILLIC_MAP = {
    "а": "a",
    "б": "b",
    "в": "v",
    "г": "h",
    "ґ": "g",
    "д": "d",
    "е": "e",
    "є": "ie",
    "ж": "zh",
    "з": "z",
    "и": "y",
    "і": "i",
    "ї": "i",
    "й": "i",
    "к": "k",
    "л": "l",
    "м": "m",
    "н": "n",
    "о": "o",
    "п": "p",
    "р": "r",
    "с": "s",
    "т": "t",
    "у": "u",
    "ф": "f",
    "х": "kh",
    "ц": "ts",
    "ч": "ch",
    "ш": "sh",
    "щ": "shch",
    "ь": "",
    "ю": "iu",
    "я": "ia",
    "ы": "y",
    "э": "e",
    "ъ": "",
}

ACCOUNT_NAME_ATTRIBUTES = (
    "sAMAccountName",
    "mailNickname",
    "userPrincipalName",
    "mail",
    "proxyAddresses",
    "otherMailbox",
)

DISPLAY_NAME_ATTRIBUTES = ("displayName", "cn", "name")

COMMON_NAME_ALIASES = {
    "artem": {"ortem"},
    "ortem": {"artem"},
    "oleksandr": {"aleksandr", "alexandr", "olexandr", "oleksander", "alexander"},
    "oleksander": {"oleksandr", "aleksandr", "alexandr", "olexandr", "alexander"},
    "aleksandr": {"oleksandr", "alexandr", "olexandr", "alexander"},
    "olexandr": {"oleksandr", "aleksandr", "alexandr", "alexander"},
    "nikita": {"mykyta", "nykyta", "mikita"},
    "mykyta": {"nikita", "nykyta", "mikita"},
    "yurii": {"yuriy", "yuri", "iurii", "iuriy"},
    "iurii": {"yurii", "yuriy", "yuri", "iuriy"},
    "illia": {"ilia", "ilya", "illiia"},
    "ilia": {"illia", "ilya", "illiia"},
    "iryna": {"irina"},
    "kyrylo": {"kirilo", "kirylo", "cyril", "cyryl"},
}


@dataclass
class UserMatch:
    user: dict[str, Any] | None
    status: str
    score: int
    note: str


def transliterate(value: str) -> str:
    return "".join(CYRILLIC_MAP.get(char, char) for char in value.lower())


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    text = transliterate(str(value))
    text = unidecode(text).lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-")


def iter_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item is not None and str(item).strip()]
    text = str(value).strip()
    return [text] if text else []


def account_local_part(value: Any) -> str:
    text = str(value).strip()
    if ":" in text and text.split(":", 1)[0].lower() in {"smtp", "sip", "x400", "x500"}:
        text = text.split(":", 1)[1]
    if "@" in text:
        text = text.split("@", 1)[0]
    return text


def normalize_hostname(hostname: str | None) -> str:
    if not hostname:
        return ""
    return normalize_text(str(hostname).split(".")[0])


def hostname_tokens(hostname: str, source_type: str | None = None) -> list[str]:
    normalized = normalize_hostname(hostname)
    parts = [part for part in normalized.split("-") if part]
    prefixes = {"vm", "old"}
    while parts and parts[0] in prefixes:
        parts = parts[1:]
    suffixes = {"pc", "nb", "notebook", "laptop", "vdi", "vm"}
    while parts and parts[-1] in suffixes:
        parts = parts[:-1]
    return parts


def _name_pairs_from_value(value: Any) -> list[tuple[str, str]]:
    text = normalize_text(value)
    if not text:
        return []
    parts = [part for part in re.split(r"[-_.]+", text) if part]
    if len(parts) < 2:
        return []
    return [(parts[0], parts[1]), (parts[1], parts[0])]


def user_name_pairs(user: dict[str, Any]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    pairs.extend(account_name_pairs(user))

    given = normalize_text(user.get("givenName"))
    surname = normalize_text(user.get("sn"))
    if given and surname:
        pairs.append((given, surname))

    initials = normalize_text(user.get("initials"))
    if initials and surname:
        pairs.append((initials, surname))

    for key in DISPLAY_NAME_ATTRIBUTES:
        for value in iter_values(user.get(key)):
            display = normalize_text(value)
            display_parts = [part for part in display.split("-") if part]
            if len(display_parts) >= 2:
                pairs.append((display_parts[0], display_parts[1]))
                pairs.append((display_parts[1], display_parts[0]))

    deduped: list[tuple[str, str]] = []
    seen = set()
    for pair in pairs:
        if pair not in seen:
            seen.add(pair)
            deduped.append(pair)
    return deduped


def account_name_pairs(user: dict[str, Any]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for key in ACCOUNT_NAME_ATTRIBUTES:
        for value in iter_values(user.get(key)):
            pairs.extend(_name_pairs_from_value(account_local_part(value)))
    return list(dict.fromkeys(pairs))


def compact_account_values(user: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ACCOUNT_NAME_ATTRIBUTES:
        for value in iter_values(user.get(key)):
            normalized = normalize_text(account_local_part(value))
            compact = normalized.replace("-", "")
            if compact:
                values.append(compact)
    return list(dict.fromkeys(values))


def token_variants(token: str) -> set[str]:
    variants = {token}
    variants.update(COMMON_NAME_ALIASES.get(token, set()))
    replacements = [
        ("ia", "ya"),
        ("iu", "yu"),
        ("ie", "ye"),
        ("yi", "i"),
        ("kh", "h"),
        ("h", "g"),
        ("ks", "x"),
    ]
    for old, new in replacements:
        for variant in list(variants):
            variants.add(variant.replace(old, new))
            variants.add(variant.replace(new, old))
    for variant in list(variants):
        if variant.startswith("y") and len(variant) > 3:
            variants.add(variant[1:])
        if variant.startswith("i") and len(variant) > 3:
            variants.add(variant[1:])
        if variant.startswith("e"):
            variants.add(f"y{variant}")
            variants.add(f"ye{variant[1:]}")
        if variant.startswith("ye"):
            variants.add(variant[1:])
        if variant.startswith("ie"):
            variants.add(f"y{variant[1:]}")
        for suffix in ("iy", "ii", "yi", "ij", "iyj", "yj"):
            if variant.endswith(suffix) and len(variant) > len(suffix) + 3:
                variants.add(variant[: -len(suffix)])
    return {variant for variant in variants if variant}


def levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (left_char != right_char)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current
    return previous[-1]


def token_match_score(host_token: str, user_token: str, allow_initial: bool = False) -> int:
    if not host_token or not user_token:
        return 0
    best = 0
    for host_variant in token_variants(host_token):
        for user_variant in token_variants(user_token):
            if host_variant == user_variant:
                best = max(best, 100)
            elif allow_initial and len(host_variant) <= 2 and user_variant.startswith(host_variant):
                best = max(best, 86 if len(host_variant) == 2 else 78)
            elif len(host_variant) >= 2 and user_variant.startswith(host_variant):
                best = max(best, 92 if len(host_variant) >= 4 else 84)
            elif len(user_variant) >= 2 and host_variant.startswith(user_variant):
                best = max(best, 90)
            elif min(len(host_variant), len(user_variant)) >= 4:
                distance = levenshtein(host_variant, user_variant)
                ratio = SequenceMatcher(None, host_variant, user_variant).ratio()
                if distance == 1:
                    best = max(best, 91)
                elif distance == 2 and ratio >= 0.78:
                    best = max(best, 84)
                elif ratio >= 0.86:
                    best = max(best, 86)
    return best


def token_prefix_match(host_token: str, user_token: str) -> bool:
    if not host_token or not user_token:
        return False
    return any(
        user_variant.startswith(host_variant)
        for host_variant in token_variants(host_token)
        for user_variant in token_variants(user_token)
    )


def pair_match_score(host_first: str, host_last: str, user_first: str, user_last: str, *, account_pair: bool) -> int:
    first_score = token_match_score(host_first, user_first)
    last_score = token_match_score(host_last, user_last, allow_initial=True)
    if first_score < 78 or last_score < 78:
        return 0

    score = min(first_score, last_score)
    if account_pair:
        score += 14
        if token_prefix_match(host_last, user_last):
            score += min(len(host_last), 6) * 3
        if token_prefix_match(host_first, user_first):
            score += min(len(host_first), 6)
    return score


def score_user(host_tokens: list[str], user: dict[str, Any]) -> int:
    if len(host_tokens) < 2:
        single = host_tokens[0] if host_tokens else ""
        if single and single in normalize_text(user.get("sAMAccountName")):
            return 45
        return 0

    host_first, host_last = host_tokens[0], host_tokens[1]
    best = 0
    for user_first, user_last in account_name_pairs(user):
        best = max(best, pair_match_score(host_first, host_last, user_first, user_last, account_pair=True))

    for user_first, user_last in user_name_pairs(user):
        best = max(best, pair_match_score(host_first, host_last, user_first, user_last, account_pair=False))

        reverse_first = token_match_score(host_first, user_last)
        reverse_last = token_match_score(host_last, user_first, allow_initial=True)
        if reverse_first >= 90 and reverse_last >= 78:
            best = max(best, min(reverse_first, reverse_last) - 8)

    first_last = f"{host_first}{host_last}"
    last_first = f"{host_last}{host_first}"
    for compact in compact_account_values(user):
        if compact == first_last or compact == last_first:
            best = max(best, 128)
        if len(host_last) >= 1 and compact.startswith(first_last):
            best = max(best, 104 + min(len(host_last), 6) * 3)
        if compact.startswith(host_first[:1]):
            account_last = compact[1:]
            last_score = token_match_score(host_last, account_last)
            if last_score >= 84:
                best = max(best, min(86, last_score))
        if compact.endswith(host_first[:1]):
            account_last = compact[:-1]
            last_score = token_match_score(host_last, account_last)
            if last_score >= 84:
                best = max(best, min(84, last_score))
        if compact.startswith(host_first[:2]):
            account_last = compact[2:]
            last_score = token_match_score(host_last, account_last)
            if last_score >= 84:
                best = max(best, min(88, last_score))
    return best


def find_best_user(hostname: str, source_type: str, users: list[dict[str, Any]]) -> UserMatch:
    tokens = hostname_tokens(hostname, source_type)
    if len(tokens) < 2:
        return UserMatch(None, "not_enough_hostname_tokens", 0, "hostname does not contain first-name and surname tokens")

    all_scored = sorted(
        ((score_user(tokens, user), user) for user in users),
        key=lambda item: item[0],
        reverse=True,
    )
    scored = [item for item in all_scored if item[0] >= 78]
    if not scored:
        candidates = [
            f"{user.get('displayName') or user.get('sAMAccountName')}:{score}"
            for score, user in all_scored[:3]
            if score > 0
        ]
        suffix = f"; closest candidates: {', '.join(candidates)}" if candidates else ""
        return UserMatch(None, "not_found", 0, f"no AD user matched tokens: {' '.join(tokens[:2])}{suffix}")

    top_score, top_user = scored[0]
    ties = [user for score, user in scored if top_score - score <= 2]
    if len(ties) > 1:
        names = ", ".join(str(user.get("displayName") or user.get("sAMAccountName")) for user in ties[:4])
        return UserMatch(None, "ambiguous", top_score, f"several AD users matched equally: {names}")

    name = top_user.get("displayName") or top_user.get("sAMAccountName")
    return UserMatch(top_user, "matched", top_score, f"matched hostname tokens {' '.join(tokens[:2])} to {name}")
