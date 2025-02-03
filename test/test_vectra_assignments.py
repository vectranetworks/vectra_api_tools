import random

import pytest
import requests

requests.packages.urllib3.disable_warnings()

global_dict = {}


@pytest.fixture()
def test_skip(vc):
    if vc.version not in [2.1, 2.2, 2.4, 2.5, 3.3, 3.4]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible via v2 and v3.3+ of API",
        )


def test_get_assignments(vc):
    assignment_gen = vc.get_all_assignments()
    results = next(assignment_gen)

    assert len(results.json()["results"]) >= 1
    assert results.json()["count"] >= 1


def test_assignments_threaded(vc, test_skip):
    count = next(vc.get_all_assignments()).json()["count"]
    vc.threads = 8
    assignment_gen = []
    for results in vc.get_all_assignments():
        assignment_gen = assignment_gen + results.json()["results"]

    assert count <= len(assignment_gen)
    vc.threads = 1


@pytest.mark.dependency()
def test_create_account_assignment(vc):
    account_id = next(vc.get_all_accounts()).json()["results"][0]["id"]
    users = []
    for results in vc.get_all_users():
        users = users + results.json()["results"]
    user = random.choice(users)
    resp = vc.create_account_assignment(account_id=account_id, user_id=user["id"])

    global_dict["account_assignment"] = resp.json()["assignment"]["id"]
    assert resp.status_code in range(200, 300)


@pytest.mark.dependency()
def test_create_host_assignment(vc, test_skip):
    host_id = next(vc.get_all_hosts()).json()["results"][0]["id"]
    users = []
    for results in vc.get_all_users():
        users = users + results.json()["results"]
    user = random.choice(users)
    resp = vc.create_host_assignment(host_id=host_id, user_id=user["id"])

    global_dict["host_assignment"] = resp.json()["assignment"]["id"]
    assert resp.status_code in range(200, 300)


@pytest.mark.dependency(depends=["test_create_account_assignment"])
def test_delete_account_assignment(vc):
    resp = vc.delete_assignment(assignment_id=global_dict.get("account_assignment", {}))
    assert resp.status_code in range(200, 300)


@pytest.mark.dependency(depends=["test_create_host_assignment"])
def test_delete_host_assignment(vc, test_skip):
    resp = vc.delete_assignment(assignment_id=global_dict.get("host_assignment", {}))
    assert resp.status_code in range(200, 300)
