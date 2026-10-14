import ipaddress
import re


HASH_PATTERNS = {
    "md5": re.compile(r"^[0-9a-fA-F]{32}$"),
    "sha1": re.compile(r"^[0-9a-fA-F]{40}$"),
    "sha256": re.compile(r"^[0-9a-fA-F]{64}$"),
}


def _is_valid_domain(value: str) -> bool:
    """Check whether a value has a valid basic DNS domain format."""

    # Accept an optional trailing dot for a fully qualified domain name.
    domain = value[:-1] if value.endswith(".") else value

    if len(domain) > 253 or "." not in domain:
        return False

    labels = domain.split(".")

    for label in labels:
        if not 1 <= len(label) <= 63:
            return False

        # Each label must begin and end with a letter or digit.
        # Hyphens are permitted inside a label.
        if not re.fullmatch(
            r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?",
            label,
        ):
            return False

    return True


def validate_indicator(value: str) -> dict:
    """
    Validate an IP address, domain name, or supported file hash.

    Returns a dictionary with the normalized indicator, its type,
    and the hash algorithm if applicable.

    Raises ValueError if the input is invalid or unsupported.
    """

    if not isinstance(value, str) or not value.strip():
        raise ValueError("Input cannot be empty and must be text.")

    candidate = value.strip()

    # 1. Check IPv4 and IPv6 addresses.
    try:
        parsed_ip = ipaddress.ip_address(candidate)

        return {
            "indicator": str(parsed_ip),
            "type": "ip",
            "hash_algorithm": None,
        }
    except ValueError:
        pass

    # Do not misclassify an invalid dotted IPv4 address as a domain.
    if re.fullmatch(r"\d+(?:\.\d+){3}", candidate):
        raise ValueError("The IPv4 address is invalid.")

    # 2. Check supported cryptographic hash formats.
    for algorithm, pattern in HASH_PATTERNS.items():
        if pattern.fullmatch(candidate):
            return {
                "indicator": candidate.lower(),
                "type": "hash",
                "hash_algorithm": algorithm,
            }

    # 3. Check the basic domain-name format.
    if _is_valid_domain(candidate):
        normalized_domain = candidate.lower()

        if normalized_domain.endswith("."):
            normalized_domain = normalized_domain[:-1]

        return {
            "indicator": normalized_domain,
            "type": "domain",
            "hash_algorithm": None,
        }

    raise ValueError(
        "Invalid indicator. Enter an IP address, domain name, "
        "or MD5/SHA-1/SHA-256 file hash."
    )