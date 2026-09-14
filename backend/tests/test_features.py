from app.features.dns_features import calculate_dns_features
from app.features.flow_features import calculate_flow_features
from app.features.timing_features import calculate_iat_features


def test_flow_features():
    result = calculate_flow_features(
        {
            "duration": 10,
            "packets": 100,
            "bytes": 10000,
        }
    )

    assert result["pps"] == 10
    assert result["bytes"] == 10000


def test_dns_features():
    result = calculate_dns_features("example.com")

    assert result["dns_query_length"] > 0
    assert result["dns_entropy"] > 0


def test_periodicity():
    result = calculate_iat_features(
        [0, 10, 20, 30, 40]
    )

    assert result["mean_iat"] == 10
    assert result["periodicity_score"] == 1
