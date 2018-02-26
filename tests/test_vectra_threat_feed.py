import pytest
import requests

requests.packages.urllib3.disable_warnings()


if not pytest.config.getoption('--token'):
    pytest.skip('v1 client not configured', allow_module_level=True)


def test_get_feeds(vc_v2):
    feeds = vc_v2.get_feeds()

    assert len(feeds.json()['threatFeeds']) > 0


def test_get_feed_by_name(vc_v2):
    feed = vc_v2.get_feeds().json()['threatFeeds'][0]
    name = feed['name']
    feed_id = feed['id']

    assert vc_v2.get_feed_by_name(name=name) == feed_id


# TODO test create_feed()
# TODO test delete_feed()
# TODO test post_stix_file()
