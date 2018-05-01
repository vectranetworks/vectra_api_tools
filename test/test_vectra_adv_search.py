import pytest
import requests

requests.packages.urllib3.disable_warnings()

if not pytest.config.getoption('--token'):
    pytest.skip('v1 client not configured', allow_module_level=True)


def test_critical_quad_host_count(vc_v2):
    basic_count = vc_v2.get_hosts(certainty_gte=50, threat_gte=50).json()['count']
    adv_count = len(vc_v2.advanced_search(stype='hosts', query='host.certainty:>=50 and host.threat:>=50').json()['results'])

    assert adv_count == basic_count


def test_ip_search(vc_v2):
    test_ip = vc_v2.get_hosts().json()['results'][-1]['last_source']
    basic_host_id = vc_v2.get_hosts(last_source=test_ip).json()['results'][0]['id']
    adv_host_id = vc_v2.advanced_search(stype='hosts', query='host.last_source:{ip}'.format(ip=test_ip)).json()['results'][0]['id']

    assert adv_host_id == basic_host_id


def test_page_size(vc_v2):
    ret_objects = len(vc_v2.advanced_search(stype='hosts', query='host.state:"active" OR host.state:"inactive"').json()['results'])
    assert ret_objects == 50

    ret_objects = len(vc_v2.advanced_search(stype='hosts', page_size=100, query='host.state:"active" OR host.state:"inactive"').json()['results'])
    assert ret_objects == 100

    ret_objects = len(vc_v2.advanced_search(stype='hosts', page_size=17, query='host.state:"active" OR host.state:"inactive"').json()['results'])
    assert ret_objects == 17


def test_medium_and_critical_detection_count(vc_v2):
    basic_count = vc_v2.get_detections(certainty_gte=50).json()['count']
    adv_count = len(vc_v2.advanced_search(stype='detections', page_size=5000, query='detection.certainty:>=50').json()['results'])

    # basic search returns triaged detections
    assert adv_count <= basic_count
