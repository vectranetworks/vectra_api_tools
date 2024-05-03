import random

import pytest
import requests

requests.packages.urllib3.disable_warnings()

global_dict = {}


@pytest.fixture()
def test_skip(vc):
    if vc.version not in [2.1, 2.2, 2.4, 2.5, 3.3]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible via v2 and v3.3+ of API",
        )


def test_get_assignments(vc):
    assignment_gen = vc.get_all_assignments()
    results = next(assignment_gen)

    assert len(results.json()["results"]) >= 1
    assert results.json()["count"] >= 1


def test_create_account_assignment(vc):
    account_id = next(vc.get_all_accounts()).json()["results"][0]["id"]
    users = []
    for results in vc.get_all_users():
        users = users + results.json()["results"]
    user = random.choice(users)
    resp = vc.create_account_assignment(account_id=account_id, user_id=user["id"])

    global_dict["account_assignment"] = resp.json()["assignment"]["id"]
    assert resp.status_code == 201


def test_create_host_assignment(vc):
    if vc.version not in [2.1, 2.2, 2.4, 2.5, 3.3]:
        pytest.skip(reason="This test is available in v2 and v3.3+ of API")
    host_id = next(vc.get_all_hosts()).json()["results"][0]["id"]
    users = []
    for results in vc.get_all_users():
        users = users + results.json()["results"]
    user = random.choice(users)
    resp = vc.create_host_assignment(host_id=host_id, user_id=user["id"])

    global_dict["host_assignment"] = resp.json()["assignment"]["id"]
    assert resp.status_code == 201


def test_create_delete_assignments(vc):
    resp1 = vc.delete_assignment(assignment_id=global_dict["account_assignment"])
    assert resp1.status_code == 204
    if vc.version in [2.1, 2.2, 2.4, 2.5, 3.3]:
        resp2 = vc.delete_assignment(assignment_id=global_dict["host_assignment"])
        assert resp2.status_code == 204
