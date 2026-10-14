
from datetime import datetime, timezone


def generate_report(aggregated: dict, risk: dict) -> dict:
    """
    Build a structured threat intelligence report.

    Args:
        aggregated: Results returned by aggregate_indicator().
        risk: Results returned by calculate_risk().

    Returns:
        A report dictionary ready for JSON serialization.
    """

    return {
        "report_generated_at": datetime.now(timezone.utc).isoformat(),
        "indicator": aggregated.get("indicator"),
        "indicator_type": aggregated.get("indicator_type"),
        "risk_assessment": {
            "score": risk.get("risk_score"),
            "level": risk.get("risk_level", "Unknown"),
            "sources_used": risk.get("sources_used", 0),
            "methodology": (
                "Heuristic average of available provider scores; "
                "not a definitive malware determination."
            ),
        },
        "provider_results": aggregated.get("provider_results", {}),
        "provider_errors": aggregated.get("provider_errors", {}),
    }
