import pytest
import requests

requests.packages.urllib3.disable_warnings()


@pytest.fixture()
def test_skip(vc):
    if vc.version not in [3.1, 3.2, 3.3]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible via v3+ of API",
        )


def test_get_entity_note_modified(vc, test_skip):
    resp = vc.get_all_entities(note_modified_timestamp_gte=100)

    assert next(resp).status_code == 200


def test_entity_generator(vc, test_skip):
    entity_gen = vc.get_all_entities(page_size=1)
    results = next(entity_gen)

    assert len(results.json()["results"]) == 1
    assert results.json()["count"] >= 1


def test_get_entity_id(vc, test_skip):
    entity = next(vc.get_all_entities()).json()["results"][0]
    entity_id = entity["id"]
    try:
        type = entity["type"]
        resp = vc.get_entity_by_id(entity_id=entity_id, type=type)
    except KeyError:
        entity_type = entity["entity_type"]
        resp = vc.get_entity_by_id(entity_id=entity_id, entity_type=entity_type)

    assert resp.json()["id"] == entity_id


def test_entity_tags(vc, test_skip):
    if vc.version < 3.3:
        pytest.skip(reason="This test is only for v3.3.")
    entity = next(vc.get_all_entities()).json()["results"][0]
    entity_id = entity["id"]
    entity_tags = entity["tags"]
    try:
        type = entity["type"]
        vc.set_entity_tags(entity_id=entity_id, tags=["pytest"], type=type)
        assert vc.get_entity_tags(entity_id=entity_id, type=type).json()["tags"] == [
            "pytest"
        ]

        vc.set_entity_tags(
            entity_id=entity_id, tags=["foo", "bar"], append=True, type=type
        )
        assert vc.get_entity_tags(entity_id=entity_id, type=type).json()["tags"] == [
            "pytest",
            "foo",
            "bar",
        ]

        vc.set_entity_tags(entity_id=entity_id, tags=entity_tags, type=type)
        assert (
            vc.get_entity_tags(entity_id=entity_id, type=type).json()["tags"]
            == entity_tags
        )

    except KeyError:
        type = entity["entity_type"]

        vc.set_entity_tags(entity_id=entity_id, tags=["pytest"], entity_type=type)
        assert vc.get_entity_tags(entity_id=entity_id, entity_type=type).json()[
            "tags"
        ] == ["pytest"]

        vc.set_entity_tags(
            entity_id=entity_id, tags=["foo", "bar"], append=True, entity_type=type
        )
        assert vc.get_entity_tags(entity_id=entity_id, entity_type=type).json()[
            "tags"
        ] == [
            "pytest",
            "foo",
            "bar",
        ]

        vc.set_entity_tags(entity_id=entity_id, tags=entity_tags, entity_type=type)
        assert (
            vc.get_entity_tags(entity_id=entity_id, entity_type=type).json()["tags"]
            == entity_tags
        )
