
import os

import requests
from dotenv import load_dotenv

load_dotenv()

BASE_URL = "https://api.abuseipdb.com/api/v2/check"


def check_ip(ip_address: str) -> dict:
    """
    Check an IP address using the AbuseIPDB API.

    Args:
        ip_address: A validated IPv4 or IPv6 address.

    Returns:
        A normalized dictionary containing IP reputation data.

    Raises:
        ValueError: If the input is not a valid IP address.
        RuntimeError: If configuration or the API request fails.
    """

    import ipaddress

    try:
        normalized_ip = str(ipaddress.ip_address(ip_address))
    except ValueError:
        raise ValueError("A valid IPv4 or IPv6 address is required.") from None

    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key or api_key == "your_abuseipdb_api_key_here":
        raise RuntimeError(
            "AbuseIPDB API key is not configured. "
            "Check your local .env file."
        )

    headers = {
        "Accept": "application/json",
        "Key": api_key,
    }

    params = {
        "ipAddress": normalized_ip,
        "maxAgeInDays": 90,
        "verbose": "",
    }

    try:
        response = requests.get(
            BASE_URL,
            headers=headers,
            params=params,
            timeout=15,
        )
    except requests.Timeout:
        raise RuntimeError(
            "AbuseIPDB request timed out. Try again later."
        ) from None
    except requests.RequestException:
        raise RuntimeError(
            "Could not connect to AbuseIPDB. "
            "Check your internet connection."
        ) from None

    if response.status_code == 401:
        raise RuntimeError(
            "AbuseIPDB rejected the API key. Check your credentials."
        )

    if response.status_code == 403:
        raise RuntimeError(
            "AbuseIPDB denied access. Check API permissions."
        )

    if response.status_code == 422:
        raise RuntimeError(
            "AbuseIPDB rejected the request parameters."
        )

    if response.status_code == 429:
        raise RuntimeError(
            "AbuseIPDB rate limit or quota reached. "
            "Wait before retrying."
        )

    if not response.ok:
        raise RuntimeError(
            f"AbuseIPDB request failed with HTTP "
            f"{response.status_code}."
        )

    try:
        payload = response.json()
    except ValueError:
        raise RuntimeError(
            "AbuseIPDB returned an invalid JSON response."
        ) from None

    data = payload.get("data")

    if not isinstance(data, dict):
        raise RuntimeError(
            "AbuseIPDB returned an unexpected response format."
        )

    return {
        "provider": "AbuseIPDB",
        "indicator": data.get("ipAddress", normalized_ip),
        "indicator_type": "ip",
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "last_reported_at": data.get("lastReportedAt"),
        "country_code": data.get("countryCode"),
        "usage_type": data.get("usageType"),
        "is_public": data.get("isPublic"),
        "is_whitelisted": data.get("isWhitelisted"),
        "report_url": (
            f"https://www.abuseipdb.com/check/{normalized_ip}"
        ),
    }
