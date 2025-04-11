import pytest

from urllib3 import disable_warnings

disable_warnings()


@pytest.fixture()
def test_skip(vc):
    if vc.version not in [2.1, 2.2, 2.4, 2.5, 3.3, 3.4]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible via v2 or v3.3+ of API",
        )


def test_host_generator(vc, test_skip):
    host_gen = vc.get_all_hosts(page_size=1)
    results = next(host_gen)

    assert results.json()["count"] >= 1
    assert len(results.json()["results"]) == 1


def test_hosts_threaded(vc, test_skip):
    count = next(vc.get_all_hosts(page_size=1)).json()["count"]
    vc.threads = 8
    host_gen = []
    for results in vc.get_all_hosts(page_size=50):
        host_gen = host_gen + results.json()["results"]

    assert count <= len(host_gen)
    vc.threads = 1


def test_get_hosts_id(vc, test_skip):
    host_id = next(vc.get_all_hosts()).json()["results"][0]["id"]
    resp = vc.get_host_by_id(host_id=host_id)

    assert resp.json()["id"] == host_id


def test_key_asset(vc, test_skip):
    host = next(vc.get_all_hosts()).json()["results"][0]
    host_id = host["id"]
    ka = host["is_key_asset"]

    vc.set_key_asset(host_id=host_id, set=False)

    vc.set_key_asset(host_id=host_id, set=True)
    assert vc.get_host_by_id(host_id=host_id).json()["is_key_asset"] is True

    vc.set_key_asset(host_id=host_id, set=False)
    assert vc.get_host_by_id(host_id=host_id).json()["is_key_asset"] is False

    vc.set_key_asset(host_id=host_id, set=ka)


def test_host_tags(vc, test_skip):
    host = next(vc.get_all_hosts()).json()["results"][0]
    host_id = host["id"]
    host_tags = host["tags"]

    vc.set_host_tags(host_id=host_id, tags=["pytest"])
    assert vc.get_host_tags(host_id=host_id).json()["tags"] == ["pytest"]

    vc.set_host_tags(host_id=host_id, tags=["foo", "bar"], append=True)
    for tag in vc.get_host_tags(host_id=host_id).json()["tags"]:
        assert tag in ["pytest", "foo", "bar"]

    vc.set_host_tags(host_id=host_id, tags=host_tags)
    assert vc.get_host_tags(host_id=host_id).json()["tags"] == host_tags
