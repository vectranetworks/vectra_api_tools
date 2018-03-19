import pytest
import requests

requests.packages.urllib3.disable_warnings()


if not pytest.config.getoption('--token'):
    pytest.skip('v1 client not configured', allow_module_level=True)

global_proxy = {}

def test_proxy_get(vc_v2):
    resp = vc_v2.get_proxies()

    assert resp.status_code == 200


def test_proxy_add(vc_v2):
    resp = vc_v2.add_proxy(address='192.168.254.254', enable=True)
    proxy = resp.json()['proxy']
    global_proxy['id'] = proxy['id']

    assert resp.status_code == 200
    assert proxy['ip'] == '192.168.254.254'
    assert proxy['considerProxy'] == True
    assert proxy['source'] == 'user'


def test_proxy_address_update(vc_v2):
    resp = vc_v2.update_proxy(proxy_id=global_proxy['id'], address='192.168.254.253')
    proxy = resp.json()['proxy']

    assert resp.status_code == 200
    assert proxy['ip'] == '192.168.254.253'
    assert proxy['considerProxy'] == True
    assert proxy['source'] == 'user'


def test_proxy_state_update(vc_v2):
    resp = vc_v2.update_proxy(proxy_id=global_proxy['id'], enable=False)
    proxy = resp.json()['proxy']

    assert resp.status_code == 200
    assert proxy['ip'] == '192.168.254.253'
    assert proxy['considerProxy'] == False
    assert proxy['source'] == 'user'
