import pytest
import requests

requests.packages.urllib3.disable_warnings()

test_vars = {}

if not pytest.config.getoption('--token'):
    pytest.skip('v1 client not configured', allow_module_level=True)


def test_create_feed(vc_v2):
    resp = vc_v2.create_feed(name='pytest', category='cnc', certainty='Medium', itype='Watchlist', duration=14)
    test_vars['threatFeed'] = resp.json()['threatFeed']['id']
    assert resp.status_code == 201


def test_get_feeds(vc_v2):
    feeds = vc_v2.get_feeds()
    assert len(feeds.json()['threatFeeds']) > 0


def test_get_feed_by_name(vc_v2):
    feed = vc_v2.get_feeds().json()['threatFeeds'][0]
    name = feed['name']
    feed_id = feed['id']
    assert vc_v2.get_feed_by_name(name=name) == feed_id


def test_post_stix_file(vc_v2):
    resp = vc_v2.post_stix_file(feed_id=test_vars['threatFeed'], stix_file='stix.xml')
    assert resp.status_code == 200


def test_delete_feed(vc_v2):
    resp = vc_v2.delete_feed(feed_id=test_vars['threatFeed'])
    assert resp.status_code == 200


