import pytest
import requests

requests.packages.urllib3.disable_warnings()


@pytest.fixture()
def test_skip(vc):
    if vc.version not in [2.1, 2.2, 2.4, 2.5, 3.2, 3.3]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible via v2 and v3.2+ of API",
        )


def test_get_group_generator(vc, test_skip):
    group_gen = vc.get_all_groups()
    results = next(group_gen)

    assert len(results.json()["results"]) >= 1
    assert results.json()["count"] >= 1


def test_create_group(vc, test_skip):
    resp = vc.create_group(
        name="pytest group",
        description="pytest group",
        type="ip",
        members=["169.254.169.254"],
        importance="high",
    )

    assert resp.status_code == 201


def test_get_group_by_id(vc, test_skip):
    groups = []
    for list in vc.get_all_groups():
        groups = groups + list.json()["results"]

    for group in groups:
        if group["name"] == "pytest group":
            test_group = group

    resp = vc.get_group_by_id(test_group["id"])
    assert resp.json()["id"] == test_group["id"]


def test_get_group_by_description(vc, test_skip):
    resp = vc.get_all_groups(description="pytest group")

    assert next(resp).json()["results"][0]["description"] == "pytest group"


def test_update_group(vc, test_skip):
    groups = []
    for list in vc.get_all_groups():
        groups = groups + list.json()["results"]

    for group in groups:
        if group["name"] == "pytest group":
            test_group = group

    vc.update_group(
        test_group["id"],
        name="pytest group update",
        description="pytest group update",
        members=["2.2.2.2"],
    )

    resp = next(vc.get_all_groups(description="pytest group update")).json()["results"][
        0
    ]
    print(resp)

    assert "2.2.2.2" in resp["members"]
    assert "pytest group update" == resp["name"]
    assert "pytest group update" == resp["description"]


def test_delete_group(vc, test_skip):
    groups = []
    for list in vc.get_all_groups():
        groups = groups + list.json()["results"]

    for group in groups:
        if group["name"] == "pytest group update":
            test_group = group
    resp = vc.delete_group(test_group["id"])

    assert resp.status_code == 204
