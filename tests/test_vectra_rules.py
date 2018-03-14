import pytest
import requests

requests.packages.urllib3.disable_warnings()

test_vars = {}

if not pytest.config.getoption('--token'):
    pytest.skip('v1 client not configured', allow_module_level=True)


@pytest.fixture()
def test_host(vc_v2):
    return vc_v2.get_hosts().json()['results'][-1]


def test_create_rule_host(vc_v2, test_host):
    host_url = test_host['url']
    resp = vc_v2.create_rule(detection_category='botnet activity', detection_type='bitcoin mining',
                             triage_category='misconfiguration', description='pytest_hostname', host=[host_url],
                             remote1_dns=['google.com'], remote1_ip=['8.8.8.8'], remote1_port=['443'])
    test_vars['host_rule_id'] = resp.json().get('id', None)
    assert resp.status_code == 201


def test_create_rule_ip(vc_v2, test_host):
    host_ip = test_host['last_source']
    resp = vc_v2.create_rule(detection_category='botnet activity', detection_type='outbound dos',
                             triage_category='misconfiguration', description='pytest_ip', ip=[host_ip],
                             remote1_dns=['google.com'], remote1_ip=['8.8.8.8'], remote1_port=['443'])
    test_vars['host_rule_ip'] = resp.json().get('id', None)
    assert resp.status_code == 201


def test_create_rule_sensor_luid(vc_v2):
    pass


def test_create_rule_all_hosts(vc_v2):
    resp = vc_v2.create_rule(detection_category='botnet activity', detection_type='abnormal ad activity',
                             triage_category='misconfiguration', description='pytest_ip', all_hosts=True,
                             remote1_dns=['google.com'], remote1_ip=['8.8.8.8'], remote1_port=['443'])
    test_vars['host_rule_all_hosts'] = resp.json().get('id', None)
    assert resp.status_code == 201


def test_update_rule_replace(vc_v2):
    pass


def test_update_rule_append(vc_v2):
    pass


def test_get_rules(vc_v2):
    # get all rules
    # get rule by id
    # get rule by name
    pass


def test_delete_rule(vc_v2):
    # delete with keep
    # delete with restore
    pass
