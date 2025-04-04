from pathlib import Path

import pytest
from urllib3 import disable_warnings

disable_warnings()
test_vars = {}


@pytest.fixture()
def test_skip(vc):
    if vc.version not in [2.1, 2.2, 2.4, 2.5, 3.3, 3.4]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible via v2 and v3.3+ of API",
        )


@pytest.fixture()
def test_skip_v2(vc):
    if vc.version not in [2.1, 2.2, 2.4, 2.5]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible via v2 of API",
        )


@pytest.fixture()
def test_skip_v3(vc):
    if vc.version not in [3.3, 3.4]:
        pytest.skip(
            allow_module_level=True,
            reason="Methodv3.3+ of API",
        )


@pytest.mark.dependency()
def test_create_feed(vc, test_skip):
    resp = vc.create_feed(
        name="pytest",
        category="cnc",
        certainty="Medium",
        itype="Watchlist",
        duration=14,
    )

    test_vars["threatFeed"] = resp.json()["threatFeed"]
    assert resp.status_code == 201


def test_get_feeds(vc, test_skip):
    feeds = vc.get_feeds()

    if 2 < vc.version < 3:
        assert len(feeds.json()["threatFeeds"]) > 0
    elif vc.version >= 3:
        assert len(feeds.json()["results"]) > 0


def test_get_feed_by_name_v2(vc, test_skip_v2):
    resp = vc.get_feeds()
    feed = resp.json()["threatFeeds"][0]

    name = feed["name"]
    feed_id = feed["id"]

    assert vc.get_feed_by_name(name=name)["id"] == feed_id


def test_get_feed_by_name_v3(vc, test_skip_v3):
    resp = vc.get_feeds()
    feed = resp.json()["results"][0]

    name = feed["name"]
    feed_id = feed["id"]

    assert vc.get_feed_by_name(name=name).json()["results"][0]["id"] == feed_id


@pytest.mark.dependency(depends=["test_create_feed"])
def test_post_stix_file(vc, test_skip):
    if Path("test/stix.xml").is_file():
        stix_file = "test/stix.xml"
    elif Path("stix.xml").is_file():
        stix_file = "stix.xml"
    resp = vc.post_stix_file(feed_id=test_vars["threatFeed"]["id"], stix_file=stix_file)

    if resp.status_code == 403:
        pass
    else:
        assert resp.status_code == 200


@pytest.mark.dependency(depends=["test_create_feed"])
def test_delete_feed(vc, test_skip):
    resp = vc.delete_feed(feed_id=test_vars["threatFeed"]["id"])

    assert resp.status_code == 200
