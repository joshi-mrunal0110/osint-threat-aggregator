
from src import aggregator


def test_aggregates_both_providers_for_ip(monkeypatch):
    def fake_virustotal(indicator):
        return {"provider": "VirusTotal", "indicator": indicator["indicator"]}

    def fake_abuseipdb(ip_address):
        return {"provider": "AbuseIPDB", "indicator": ip_address}

    monkeypatch.setattr(aggregator, "get_report", fake_virustotal)
    monkeypatch.setattr(aggregator, "check_ip", fake_abuseipdb)

    result = aggregator.aggregate_indicator({
        "indicator": "8.8.8.8",
        "type": "ip",
    })

    assert result["indicator"] == "8.8.8.8"
    assert "VirusTotal" in result["provider_results"]
    assert "AbuseIPDB" in result["provider_results"]
    assert result["provider_errors"] == {}


def test_domain_skips_abuseipdb(monkeypatch):
    monkeypatch.setattr(
        aggregator,
        "get_report",
        lambda indicator: {"provider": "VirusTotal"},
    )

    def unexpected_abuse_check(ip_address):
        raise AssertionError("AbuseIPDB should not be called for a domain")

    monkeypatch.setattr(aggregator, "check_ip", unexpected_abuse_check)

    result = aggregator.aggregate_indicator({
        "indicator": "example.com",
        "type": "domain",
    })

    assert "VirusTotal" in result["provider_results"]
    assert result["provider_results"]["AbuseIPDB"]["status"] == "not_applicable"


def test_one_provider_failure_preserves_other_result(monkeypatch):
    monkeypatch.setattr(
        aggregator,
        "get_report",
        lambda indicator: {"provider": "VirusTotal", "status": "success"},
    )

    def failing_abuse_check(ip_address):
        raise RuntimeError("Test provider failure")

    monkeypatch.setattr(aggregator, "check_ip", failing_abuse_check)

    result = aggregator.aggregate_indicator({
        "indicator": "8.8.8.8",
        "type": "ip",
    })

    assert result["provider_results"]["VirusTotal"]["status"] == "success"
    assert "AbuseIPDB" in result["provider_errors"]
    assert result["provider_errors"]["AbuseIPDB"] == "Test provider failure"


def test_both_provider_failures_are_recorded(monkeypatch):
    def failing_virustotal(indicator):
        raise RuntimeError("VirusTotal unavailable")

    def failing_abuse_check(ip_address):
        raise RuntimeError("AbuseIPDB unavailable")

    monkeypatch.setattr(aggregator, "get_report", failing_virustotal)
    monkeypatch.setattr(aggregator, "check_ip", failing_abuse_check)

    result = aggregator.aggregate_indicator({
        "indicator": "8.8.8.8",
        "type": "ip",
    })

    assert result["provider_results"] == {}
    assert "VirusTotal" in result["provider_errors"]
    assert "AbuseIPDB" in result["provider_errors"]
