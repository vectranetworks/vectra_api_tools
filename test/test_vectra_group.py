import pytest

from urllib3 import disable_warnings

disable_warnings()


@pytest.fixture()
def test_skip(vc):
    if vc.version not in [2.1, 2.2, 2.4, 2.5, 3.2, 3.3, 3.4]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible via v2 and v3.2+ of API",
        )


@pytest.fixture()
def test_skip_34(vc):
    if vc.version not in [3.4]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible v3.4+ of API",
        )


def test_get_group_generator(vc, test_skip):
    group_gen = vc.get_all_groups()
    results = next(group_gen)

    assert len(results.json()["results"]) >= 1
    assert results.json()["count"] >= 1


def test_groups_threaded(vc, test_skip):
    count = next(vc.get_all_groups(page_size=1)).json()["count"]
    vc.threads = 8
    group_gen = []
    for results in vc.get_all_groups(page_size=50):
        group_gen = group_gen + results.json()["results"]

    assert count <= len(group_gen)
    vc.threads = 1


@pytest.mark.dependency()
def test_create_group(vc, test_skip):
    resp = vc.create_group(
        name="pytest group",
        description="pytest group",
        type="ip",
        members=["169.254.169.254"],
        importance="high",
    )

    # assume successful creation if returns already exists?
    assert resp.status_code in [201, 409]


@pytest.mark.dependency(depends=["test_create_group"])
def test_get_group_by_id(vc, test_skip):
    """
    Find the group we created in test_create_group
    """
    groups = []
    for results in vc.get_all_groups():
        groups = groups + results.json()["results"]

    test_group = [x for x in groups if x["name"] == "pytest group"][0]

    resp = vc.get_group_by_id(test_group["id"])
    assert resp.json()["id"] == test_group["id"]


@pytest.mark.dependency(depends=["test_create_group"])
def test_get_group_by_description(vc, test_skip):
    resp = vc.get_all_groups(description="pytest group")

    assert next(resp).json()["results"][0]["description"] == "pytest group"


@pytest.mark.dependency(depends=["test_create_group"])
def test_update_group(vc, test_skip):
    resp = vc.get_all_groups(description="pytest group")
    test_group = next(resp).json()["results"][0]

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


@pytest.mark.dependency(depends=["test_create_group"])
def test_append_group(vc, test_skip):
    resp = vc.get_all_groups(description="pytest group update")
    test_group = next(resp).json()["results"][0]

    members = [f"2.2.3.{x}" for x in range(10, 250)]

    vc.update_group(
        test_group["id"],
        members=members,
        append=True,
    )

    resp = next(vc.get_all_groups(description="pytest group update")).json()["results"][
        0
    ]
    print(resp)

    assert "2.2.2.2" in resp["members"]
    assert len(resp["members"]) == 241


@pytest.mark.dependency(depends=["test_create_group"])
def test_delete_group(vc, test_skip):
    groups = []
    for results in vc.get_all_groups():
        groups = groups + results.json()["results"]

    for group in groups:
        if group["name"] == "pytest group update":
            test_group = group
    resp = vc.delete_group(test_group["id"])

    assert resp.status_code == 204


@pytest.mark.dependency()
def test_create_regex_group(vc, test_skip_34):
    resp = vc.create_group(
        name="pytest regex group",
        description="pytest regex group",
        type="account",
        regex=".*",
        importance="high",
    )

    assert resp.status_code == 201


@pytest.mark.dependency(depends=["test_create_regex_group"])
def test_update_regex_group(vc, test_skip_34):
    groups = []
    for results in vc.get_all_groups():
        groups = groups + results.json()["results"]

    for group in groups:
        if group["name"] == "pytest regex group":
            test_group = group

    vc.update_group(
        test_group["id"],
        name="pytest group regex update",
        description="pytest group regex update",
        regex=r"\s*",
    )

    resp = next(vc.get_all_groups(description="pytest group regex update")).json()[
        "results"
    ][0]
    print(resp)

    assert r"\s*" in resp["regex"]
    assert "pytest group regex update" == resp["name"]
    assert "pytest group regex update" == resp["description"]


@pytest.mark.dependency(depends=["test_create_regex_group"])
def test_delete_regex_group(vc, test_skip_34):
    groups = []
    for results in vc.get_all_groups():
        groups = groups + results.json()["results"]

    for group in groups:
        if group["name"] == "pytest group regex update":
            test_group = group
    resp = vc.delete_group(test_group["id"])

    assert resp.status_code == 204
