
import os

import requests
from dotenv import load_dotenv

load_dotenv()

BASE_URL = "https://www.virustotal.com/api/v3"


def get_report(indicator: dict) -> dict:
    """
    Retrieve a VirusTotal report for a validated indicator.

    Supported types:
        - ip
        - domain
        - hash

    Returns a normalized report dictionary.
    Raises ValueError or RuntimeError for invalid inputs and API errors.
    """

    api_key = os.getenv("VT_API_KEY")

    if not api_key or api_key == "your_virustotal_api_key_here":
        raise RuntimeError(
            "VirusTotal API key is not configured. "
            "Check your local .env file."
        )

    value = indicator["indicator"]
    indicator_type = indicator["type"]

    endpoints = {
        "ip": f"{BASE_URL}/ip_addresses/{value}",
        "domain": f"{BASE_URL}/domains/{value}",
        "hash": f"{BASE_URL}/files/{value}",
    }

    if indicator_type not in endpoints:
        raise ValueError(
            f"Unsupported indicator type: {indicator_type}"
        )

    try:
        response = requests.get(
            endpoints[indicator_type],
            headers={
                "accept": "application/json",
                "x-apikey": api_key,
            },
            timeout=15,
        )
    except requests.Timeout:
        raise RuntimeError(
            "VirusTotal request timed out. Try again later."
        ) from None
    except requests.RequestException:
        raise RuntimeError(
            "Could not connect to VirusTotal. "
            "Check your internet connection."
        ) from None

    if response.status_code == 401:
        raise RuntimeError(
            "VirusTotal rejected the API key. "
            "Check your credentials."
        )

    if response.status_code == 403:
        raise RuntimeError(
            "VirusTotal denied access. Check API permissions."
        )

    if response.status_code == 404:
        raise RuntimeError(
            "No report was found for this indicator."
        )

    if response.status_code == 429:
        raise RuntimeError(
            "VirusTotal rate limit or quota reached. "
            "Wait before retrying."
        )

    if not response.ok:
        raise RuntimeError(
            f"VirusTotal request failed with HTTP "
            f"{response.status_code}."
        )

    try:
        payload = response.json()
    except ValueError:
        raise RuntimeError(
            "VirusTotal returned an invalid JSON response."
        ) from None

    data = payload.get("data", {})
    attributes = data.get("attributes", {})

    stats = attributes.get("last_analysis_stats")
    analysis_stats = None

    if isinstance(stats, dict):
        keys = (
            "malicious",
            "suspicious",
            "harmless",
            "undetected",
            "timeout",
        )

        analysis_stats = {
            key: stats.get(key, 0)
            for key in keys
        }

    gui_types = {
        "ip": "ip-address",
        "domain": "domain",
        "hash": "file",
    }

    return {
        "provider": "VirusTotal",
        "indicator": value,
        "indicator_type": indicator_type,
        "reputation": attributes.get("reputation"),
        "analysis_stats": analysis_stats,
        "last_analysis_date": attributes.get(
            "last_analysis_date"
        ),
        "report_url": (
            f"https://www.virustotal.com/gui/"
            f"{gui_types[indicator_type]}/{value}"
        ),
    }
