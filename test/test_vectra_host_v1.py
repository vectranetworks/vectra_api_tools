import pytest
import requests

requests.packages.urllib3.disable_warnings()


if not pytest.config.getoption('--user'):
    pytest.skip('v1 client not configured', allow_module_level=True)


def test_get_hosts(vc_v1):
    resp = vc_v1.get_hosts()

    assert vc_v1.version == 1
    assert resp.status_code == 200


def test_host_generator(vc_v1):
    host_gen = vc_v1.get_all_hosts(page_size=1)
    results = next(host_gen)

    assert len(results.json()['results']) == 1
    assert results.json()['count'] > 1


def test_get_hosts_id(vc_v1):
    host_id = vc_v1.get_hosts().json()['results'][0]['id']
    resp = vc_v1.get_host_by_id(host_id=host_id)

    assert resp.json()['id'] == host_id

