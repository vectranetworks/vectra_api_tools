import pytest
import requests

requests.packages.urllib3.disable_warnings()


@pytest.fixture()
def test_skip(vc):
    if vc.version not in [2.1, 2.2, 2.4, 2.5, 3.3]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible via v2 and v3.3+ of API",
        )


def test_get_user_generator(vc, test_skip):
    user_gen = vc.get_all_users()
    results = next(user_gen)

    assert len(results.json()["results"]) >= 1
    assert results.json()["count"] >= 1


def test_get_user_by_username(vc, test_skip):
    user = next(vc.get_all_users()).json()["results"][0]
    username = user["username"]
    resp = vc.get_user_by_name(username=username)

    assert resp.json()["results"][0]["username"] == username


def test_get_user_by_id(vc):
    if vc.version not in [2.1, 2.2, 2.4, 2.5]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible via v2 of API",
        )
    user = next(vc.get_all_users()).json()["results"][0]
    user_id = user["id"]
    resp = vc.get_user_by_id(user_id=user_id)

    assert resp.json()["id"] == user_id


def test_update_user(vc):
    if vc.version not in [2.1, 2.2, 2.4, 2.5]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible via v2 of API",
        )
    resp = vc.get_user_by_name(username="API-test")
    user_id = resp.json()["results"][0]["id"]
    resp = vc.update_user(
        user_id=user_id, account_type="local", authentication_profile=None
    )

    assert resp.json()["id"] == user_id
