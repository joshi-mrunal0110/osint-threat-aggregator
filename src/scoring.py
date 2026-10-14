
def calculate_risk(report: dict) -> dict:
    """
    Calculate a preliminary risk score from aggregated
    VirusTotal and AbuseIPDB intelligence.

    This is a heuristic for triage, not a definitive
    determination that an indicator is malicious.
    """

    scores = []

    # VirusTotal detection ratio.
    vt = report.get("provider_results", {}).get("VirusTotal", {})
    stats = vt.get("analysis_stats")

    if isinstance(stats, dict):
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        timeout = stats.get("timeout", 0)

        values = [malicious, suspicious, harmless, undetected, timeout]

        if all(isinstance(v, (int, float)) and not isinstance(v, bool)
               and v >= 0 for v in values):
            total = sum(values)

            if total > 0:
                vt_score = round(
                    100 * (malicious + 0.5 * suspicious) / total
                )
                scores.append(vt_score)

    # AbuseIPDB confidence score.
    abuse = report.get("provider_results", {}).get("AbuseIPDB", {})
    abuse_score = abuse.get("abuse_confidence_score")

    if (
        isinstance(abuse_score, (int, float))
        and not isinstance(abuse_score, bool)
        and 0 <= abuse_score <= 100
    ):
        scores.append(round(abuse_score))

    if not scores:
        return {
            "risk_score": None,
            "risk_level": "Unknown",
            "sources_used": 0,
        }

    # Average the available provider scores.
    risk_score = round(sum(scores) / len(scores))

    if risk_score >= 80:
        risk_level = "Critical"
    elif risk_score >= 60:
        risk_level = "High"
    elif risk_score >= 30:
        risk_level = "Medium"
    elif risk_score > 0:
        risk_level = "Low"
    else:
        risk_level = "Low"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "sources_used": len(scores),
    }
