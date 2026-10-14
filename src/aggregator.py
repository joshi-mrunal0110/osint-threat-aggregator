
from src.providers.virustotal import get_report
from src.providers.abuseipdb import check_ip


def aggregate_indicator(indicator: dict) -> dict:
    """
    Collect threat intelligence from available providers.

    VirusTotal supports IP addresses, domains, and file hashes.
    AbuseIPDB supports IP addresses only.

    A failure from one provider does not discard another
    provider's successful result.
    """

    value = indicator["indicator"]
    indicator_type = indicator["type"]

    provider_results = {}
    provider_errors = {}

    # Query VirusTotal.
    try:
        provider_results["VirusTotal"] = get_report(indicator)
    except (RuntimeError, ValueError) as error:
        provider_errors["VirusTotal"] = str(error)

    # Query AbuseIPDB only for IP addresses.
    if indicator_type == "ip":
        try:
            provider_results["AbuseIPDB"] = check_ip(value)
        except (RuntimeError, ValueError) as error:
            provider_errors["AbuseIPDB"] = str(error)
    else:
        provider_results["AbuseIPDB"] = {
            "status": "not_applicable",
            "reason": "AbuseIPDB checks IP addresses only.",
        }

    return {
        "indicator": value,
        "indicator_type": indicator_type,
        "provider_results": provider_results,
        "provider_errors": provider_errors,
    }
