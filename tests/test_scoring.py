
from src.scoring import calculate_risk


def test_critical_risk_from_virustotal():
    report = {
        "provider_results": {
            "VirusTotal": {
                "analysis_stats": {
                    "malicious": 80,
                    "suspicious": 5,
                    "harmless": 10,
                    "undetected": 5,
                    "timeout": 0,
                }
            }
        }
    }

    result = calculate_risk(report)

    assert result["risk_score"] == 82
    assert result["risk_level"] == "Critical"
    assert result["sources_used"] == 1


def test_high_risk_from_abuseipdb():
    report = {
        "provider_results": {
            "AbuseIPDB": {
                "abuse_confidence_score": 75
            }
        }
    }

    result = calculate_risk(report)

    assert result["risk_score"] == 75
    assert result["risk_level"] == "High"
    assert result["sources_used"] == 1


def test_average_score_from_both_providers():
    report = {
        "provider_results": {
            "VirusTotal": {
                "analysis_stats": {
                    "malicious": 4,
                    "suspicious": 0,
                    "harmless": 4,
                    "undetected": 2,
                    "timeout": 0,
                }
            },
            "AbuseIPDB": {
                "abuse_confidence_score": 80
            },
        }
    }

    result = calculate_risk(report)

    # VirusTotal score = 40; AbuseIPDB score = 80.
    # Average = 60.
    assert result["risk_score"] == 60
    assert result["risk_level"] == "High"
    assert result["sources_used"] == 2


def test_zero_score_is_low_risk():
    report = {
        "provider_results": {
            "AbuseIPDB": {
                "abuse_confidence_score": 0
            }
        }
    }

    result = calculate_risk(report)

    assert result["risk_score"] == 0
    assert result["risk_level"] == "Low"


def test_missing_data_returns_unknown():
    report = {
        "provider_results": {},
        "provider_errors": {
            "VirusTotal": "Unavailable",
            "AbuseIPDB": "Unavailable",
        },
    }

    result = calculate_risk(report)

    assert result["risk_score"] is None
    assert result["risk_level"] == "Unknown"
    assert result["sources_used"] == 0


def test_invalid_abuse_score_is_ignored():
    report = {
        "provider_results": {
            "AbuseIPDB": {
                "abuse_confidence_score": 150
            }
        }
    }

    result = calculate_risk(report)

    assert result["risk_score"] is None
    assert result["risk_level"] == "Unknown"
