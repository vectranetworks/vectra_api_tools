"""
Test /health API endpoint
"""

import pytest
from urllib3 import disable_warnings

disable_warnings()


@pytest.fixture()
def test_skip(vc):
    if vc.version not in [2.1, 2.2, 2.4, 2.5, 3.3, 3.4]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible via v2 and v3.3+ of API",
        )


@pytest.fixture()
def test_skip_34(vc):
    """
    Fixture to skip tests if the brain is not v3.4 or later"""
    if vc.version not in [3.4]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible v3.4+ of API",
        )


def test_get_health(vc, test_skip):
    resp = vc.get_health_check()

    assert resp.status_code == 200


def test_get_health_check(vc, test_skip):
    """
    Test system health checks for QuadUX brains
    """
    for c in [
        "network",
        "system",
        "memory",
        "sensors",
        "hostid",
        "disk",
        "cpu",
        "power",
        "connectivity",
        "trafficdrop",
    ]:
        resp = vc.get_health_check(check=c)
        assert resp.status_code == 200


def test_get_health_check_3_4(vc, test_skip_34):
    """
    Test system health checks for RUX brains running 3.4 or later
    """
    for c in [
        "detection",
        "external_connectors",
        "external_connectors/details",
        "edr",
        "edr/details",
        "network_brain/ping",
    ]:
        resp = vc.get_health_check(check=c)
        assert resp.status_code == 200
