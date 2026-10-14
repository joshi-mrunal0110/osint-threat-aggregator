
from datetime import datetime

from src.report import generate_report


def test_generate_report_contains_expected_fields():
    aggregated = {
        "indicator": "8.8.8.8",
        "indicator_type": "ip",
        "provider_results": {
            "VirusTotal": {"reputation": 10},
            "AbuseIPDB": {"abuse_confidence_score": 20},
        },
        "provider_errors": {},
    }

    risk = {
        "risk_score": 15,
        "risk_level": "Low",
        "sources_used": 2,
    }

    report = generate_report(aggregated, risk)

    assert report["indicator"] == "8.8.8.8"
    assert report["indicator_type"] == "ip"
    assert report["risk_assessment"]["score"] == 15
    assert report["risk_assessment"]["level"] == "Low"
    assert report["risk_assessment"]["sources_used"] == 2
    assert "VirusTotal" in report["provider_results"]
    assert "AbuseIPDB" in report["provider_results"]


def test_report_timestamp_is_valid_utc_iso_format():
    report = generate_report(
        {
            "indicator": "example.com",
            "indicator_type": "domain",
            "provider_results": {},
            "provider_errors": {},
        },
        {"risk_score": None, "risk_level": "Unknown", "sources_used": 0},
    )

    timestamp = datetime.fromisoformat(report["report_generated_at"])

    assert timestamp.tzinfo is not None
    assert timestamp.utcoffset().total_seconds() == 0


def test_report_preserves_provider_errors():
    aggregated = {
        "indicator": "8.8.8.8",
        "indicator_type": "ip",
        "provider_results": {
            "VirusTotal": {"reputation": 0},
        },
        "provider_errors": {
            "AbuseIPDB": "Provider unavailable",
        },
    }

    risk = {
        "risk_score": 0,
        "risk_level": "Low",
        "sources_used": 1,
    }

    report = generate_report(aggregated, risk)

    assert report["provider_errors"]["AbuseIPDB"] == "Provider unavailable"


def test_missing_risk_data_defaults_to_unknown():
    report = generate_report(
        {
            "indicator": "example.com",
            "indicator_type": "domain",
        },
        {},
    )

    assert report["risk_assessment"]["score"] is None
    assert report["risk_assessment"]["level"] == "Unknown"
    assert report["risk_assessment"]["sources_used"] == 0
    assert report["provider_results"] == {}
    assert report["provider_errors"] == {}
