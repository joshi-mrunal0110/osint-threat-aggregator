import pytest

from src.validator import validate_indicator


@pytest.mark.parametrize(
    ("value", "expected_type", "expected_indicator", "expected_algorithm"),
    [
        ("8.8.8.8", "ip", "8.8.8.8", None),
        (
            "2001:4860:4860::8888",
            "ip",
            "2001:4860:4860::8888",
            None,
        ),
        (" EXAMPLE.COM ", "domain", "example.com", None),
        ("Example.COM.", "domain", "example.com", None),
        (
            "d41d8cd98f00b204e9800998ecf8427e",
            "hash",
            "d41d8cd98f00b204e9800998ecf8427e",
            "md5",
        ),
        (
            "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
            "hash",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "sha1",
        ),
        (
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
            "hash",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
            "sha256",
        ),
    ],
)
def test_valid_indicators(
    value, expected_type, expected_indicator, expected_algorithm
):
    result = validate_indicator(value)

    assert result["type"] == expected_type
    assert result["indicator"] == expected_indicator
    assert result["hash_algorithm"] == expected_algorithm


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        None,
        "999.999.999.999",
        "bad_domain.com",
        "https://example.com",
        "abc123",
        "da39a3ee5e6b4b0d3255bfef95601890afd8070",
    ],
)
def test_invalid_indicators(value):
    with pytest.raises(ValueError):
        validate_indicator(value)