
import pytest
import requests

from src.providers.abuseipdb import check_ip


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.ok = 200 <= status_code < 400

    def json(self):
        return self._payload


@pytest.fixture
def mock_api_key(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test_api_key")


def test_successful_ip_check(monkeypatch, mock_api_key):
    payload = {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 12,
            "totalReports": 5,
            "lastReportedAt": "2026-10-01T10:00:00+00:00",
            "countryCode": "US",
            "usageType": "Data Center/Web Hosting/Transit",
            "isPublic": True,
            "isWhitelisted": False,
        }
    }

    def fake_get(url, headers, params, timeout):
        assert url == "https://api.abuseipdb.com/api/v2/check"
        assert headers["Key"] == "test_api_key"
        assert params["ipAddress"] == "8.8.8.8"
        assert timeout == 15
        return FakeResponse(200, payload)

    monkeypatch.setattr(requests, "get", fake_get)

    result = check_ip("8.8.8.8")

    assert result["provider"] == "AbuseIPDB"
    assert result["indicator"] == "8.8.8.8"
    assert result["abuse_confidence_score"] == 12
    assert result["total_reports"] == 5
    assert result["country_code"] == "US"
    assert result["is_public"] is True


def test_invalid_ip_is_rejected(monkeypatch, mock_api_key):
    def unexpected_request(*args, **kwargs):
        pytest.fail("API request should not be made for an invalid IP")

    monkeypatch.setattr(requests, "get", unexpected_request)

    with pytest.raises(ValueError, match="valid IPv4 or IPv6"):
        check_ip("not-an-ip")


def test_missing_api_key(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="API key is not configured"):
        check_ip("8.8.8.8")


def test_rate_limit_error(monkeypatch, mock_api_key):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *args, **kwargs: FakeResponse(429, {}),
    )

    with pytest.raises(RuntimeError, match="rate limit or quota"):
        check_ip("8.8.8.8")


def test_timeout_error(monkeypatch, mock_api_key):
    def fake_get(*args, **kwargs):
        raise requests.Timeout()

    monkeypatch.setattr(requests, "get", fake_get)

    with pytest.raises(RuntimeError, match="request timed out"):
        check_ip("8.8.8.8")
