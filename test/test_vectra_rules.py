import pytest
import requests

requests.packages.urllib3.disable_warnings()

test_vars = {}

if not pytest.config.getoption('--token'):
    pytest.skip('v2 client not configured', allow_module_level=True)


@pytest.fixture()
def test_host(vc_v2):
    return vc_v2.get_hosts().json()['results'][-1]


@pytest.fixture()
def test_host2(vc_v2):
    return vc_v2.get_hosts().json()['results'][-2]

# TODO Group tests into classes; host, ip, sensor_luid, all_hosts


def test_create_rule_host(vc_v2, test_host):
    resp = vc_v2.create_rule(detection_category='botnet activity', detection_type='cryptocurrency mining',
                             triage_category='misconfiguration', description='pytest_hostname', host=[test_host['url']],
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
    resp = vc_v2.create_rule(detection_category='botnet activity', detection_type='outbound port sweep',
                             triage_category='misconfiguration', description='pytest_all', all_hosts=True,
                             remote1_port=['443'])
    test_vars['host_rule_all_hosts'] = resp.json().get('id', None)
    assert resp.status_code == 201


def test_get_rules(vc_v2):
    resp = vc_v2.get_rules().json()
    assert resp['count'] >= 3

    resp2 = vc_v2.get_rules(name='pytest_hostname')
    assert resp2['description'] == 'pytest_hostname'


def test_update_rule_replace(vc_v2, test_host2):
    host_url = test_host2['url']
    resp = vc_v2.update_rule(rule_id=test_vars['host_rule_id'], host=[host_url], remote1_dns=['foo.com'],
                             remote1_ip=['4.4.4.4'], remote1_port=['8443'])
    assert resp.status_code == 200

    resp2 = vc_v2.get_rules(rule_id=test_vars['host_rule_id']).json()
    assert [host_url] == resp2['host']
    assert ['foo.com'] == resp2['remote1_dns']
    assert ['4.4.4.4'] == resp2['remote1_ip']
    assert ['8443'] == resp2['remote1_port']


def test_update_rule_append(vc_v2, test_host):
    resp = vc_v2.update_rule(rule_id=test_vars['host_rule_ip'], append = True, ip=['254.254.254.254'],
                             remote1_dns=['foo.com'], remote1_ip=['4.4.4.4'], remote1_port=['8443'])
    assert resp.status_code == 200

    resp2 = vc_v2.get_rules(rule_id=test_vars['host_rule_ip']).json()
    assert all(ip in resp2['ip'] for ip in [test_host['last_source'], '254.254.254.254'])
    assert all(domain in resp2['remote1_dns'] for domain in ['google.com', 'foo.com'])
    assert all(ip in resp2['remote1_ip'] for ip in ['8.8.8.8', '4.4.4.4'])
    assert all(port in resp2['remote1_port'] for port in ['443', '8443'])


def test_delete_rule(vc_v2):
    resp1 = vc_v2.delete_rule(rule_id=test_vars['host_rule_id']).json()
    resp2 = vc_v2.delete_rule(rule_id=test_vars['host_rule_ip']).json()
    resp3 = vc_v2.delete_rule(rule_id=test_vars['host_rule_all_hosts']).json()

    assert all(resp['_meta']['level'] == 'success' for resp in [resp1, resp2, resp3])
