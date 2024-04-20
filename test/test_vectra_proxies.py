import pytest
import requests

requests.packages.urllib3.disable_warnings()

global_proxy = {}


@pytest.fixture()
def test_skip(vc):
    if vc.version not in [2.1, 2.2, 2.4, 2.5, 3.3]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible via v2 and v3.3+ of API",
        )


def test_proxy_get(vc, test_skip):
    resp = vc.get_proxies()

    assert resp.status_code == 200


def test_proxy_add(vc, test_skip):
    resp = vc.add_proxy(address="169.254.254.254", enable=True)

    proxy = resp.json()["proxy"]

    global_proxy["id"] = proxy["id"]

    assert resp.status_code == 200
    assert proxy["ip"] == "169.254.254.254"
    assert proxy["considerProxy"] is True


def test_proxy_address_update(vc, test_skip):
    resp = vc.update_proxy(proxy_id=global_proxy["id"], address="169.254.254.253")

    proxy = resp.json()["proxy"]
    assert resp.status_code == 200
    assert proxy["ip"] == "169.254.254.253"
    assert proxy["considerProxy"] is True


def test_proxy_state_update(vc, test_skip):
    resp = vc.update_proxy(proxy_id=global_proxy["id"], enable=False)
    if resp.status_code == 403:
        pytest.skip(
            reason="Insufficient permissions for test.",
        )

    proxy = resp.json()["proxy"]
    assert resp.status_code == 200
    assert proxy["ip"] == "169.254.254.253"
    assert proxy["considerProxy"] is False

    # The Proxy ID is updated when considerProxy is changed to False
    resp = vc.get_proxies()
    for p in resp.json()["proxies"]:
        if p["address"] == proxy["ip"]:
            global_proxy["id"] = p["id"]


def test_proxy_delete(vc, test_skip):
    resp = vc.delete_proxy(proxy_id=global_proxy["id"])

    assert resp.status_code == 204
