import pytest
import requests

requests.packages.urllib3.disable_warnings()


if not pytest.config.getoption('--token'):
    pytest.skip('v1 client not configured', allow_module_level=True)


def test_get_hosts(vc_v2):
    resp = vc_v2.get_hosts()

    assert vc_v2.version == 2
    assert resp.status_code == 200


def test_host_generator(vc_v2):
    host_gen = vc_v2.get_all_hosts(page_size=1)
    results = next(host_gen)

    assert len(results.json()['results']) == 1
    assert results.json()['count'] > 1


def test_get_hosts_id(vc_v2):
    host_id = vc_v2.get_hosts().json()['results'][0]['id']
    resp = vc_v2.get_host_by_id(host_id=host_id)

    assert resp.json()['id'] == host_id


def test_key_asset(vc_v2):
    host = vc_v2.get_hosts().json()['results'][0]
    host_id = host['id']
    ka = host['is_key_asset']

    vc_v2.set_key_asset(host_id=host_id, set=False)

    vc_v2.set_key_asset(host_id=host_id, set=True)
    assert vc_v2.get_host_by_id(host_id=host_id).json()['is_key_asset'] == True

    vc_v2.set_key_asset(host_id=host_id, set=False)
    assert vc_v2.get_host_by_id(host_id=host_id).json()['is_key_asset'] == False

    vc_v2.set_key_asset(host_id=host_id, set=ka)


def test_host_tags(vc_v2):
    host = vc_v2.get_hosts().json()['results'][0]
    host_id = host['id']
    host_tags = host['tags']

    vc_v2.set_host_tags(host_id=host_id, tags=['pytest'])
    assert vc_v2.get_host_tags(host_id=host_id).json()['tags'] == ['pytest']

    vc_v2.set_host_tags(host_id=host_id, tags=['foo', 'bar'], append=True)
    assert vc_v2.get_host_tags(host_id=host_id).json()['tags'] == ['pytest', 'foo', 'bar']

    vc_v2.set_host_tags(host_id=host_id, tags=host_tags)
    assert vc_v2.get_host_tags(host_id=host_id).json()['tags'] == host_tags

