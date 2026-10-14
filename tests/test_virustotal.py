
import requests
import pytest

from src.providers.virustotal import get_report


class FakeResponse:
    """Simulate an HTTP response without contacting VirusTotal."""

    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self.payload = payload if payload is not None else {}
        self.ok = 200 <= status_code < 400

    def json(self):
        return self.payload


@pytest.fixture
def valid_indicator():
    return {
        "indicator": "8.8.8.8",
        "type": "ip",
        "hash_algorithm": None,
    }


@pytest.fixture
def mock_api_key(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key")


def test_successful_report(
    monkeypatch, valid_indicator, mock_api_key
):
    payload = {
        "data": {
            "attributes": {
                "reputation": 5,
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "harmless": 70,
                    "undetected": 10,
                    "timeout": 0,
                },
                "last_analysis_date": 1700000000,
            }
        }
    }

    def fake_get(url, headers, timeout):
        assert url.endswith("/ip_addresses/8.8.8.8")
        assert headers["x-apikey"] == "test-key"
        assert timeout == 15
        return FakeResponse(200, payload)

    monkeypatch.setattr(
        "src.providers.virustotal.requests.get",
        fake_get,
    )

    report = get_report(valid_indicator)

    assert report["provider"] == "VirusTotal"
    assert report["indicator"] == "8.8.8.8"
    assert report["indicator_type"] == "ip"
    assert report["reputation"] == 5
    assert report["analysis_stats"]["malicious"] == 2
    assert report["analysis_stats"]["suspicious"] == 1
    assert report["last_analysis_date"] == 1700000000


def test_missing_api_key(monkeypatch, valid_indicator):
    monkeypatch.delenv("VT_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="API key"):
        get_report(valid_indicator)


def test_report_not_found(
    monkeypatch, valid_indicator, mock_api_key
):
    monkeypatch.setattr(
        "src.providers.virustotal.requests.get",
        lambda *args, **kwargs: FakeResponse(404),
    )

    with pytest.raises(RuntimeError, match="No report"):
        get_report(valid_indicator)


def test_rate_limit(
    monkeypatch, valid_indicator, mock_api_key
):
    monkeypatch.setattr(
        "src.providers.virustotal.requests.get",
        lambda *args, **kwargs: FakeResponse(429),
    )

    with pytest.raises(RuntimeError, match="rate limit"):
        get_report(valid_indicator)


def test_connection_timeout(
    monkeypatch, valid_indicator, mock_api_key
):
    def fake_timeout(*args, **kwargs):
        raise requests.Timeout()

    monkeypatch.setattr(
        "src.providers.virustotal.requests.get",
        fake_timeout,
    )

    with pytest.raises(RuntimeError, match="timed out"):
        get_report(valid_indicator)
