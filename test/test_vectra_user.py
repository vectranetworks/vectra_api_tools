import pytest
from urllib3 import disable_warnings

disable_warnings()


@pytest.fixture()
def test_skip(vc):
    if vc.version not in [2.1, 2.2, 2.4, 2.5, 3.3, 3.4]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible via v2 and v3.3+ of API",
        )


@pytest.fixture()
def test_skip_2(vc):
    if vc.version not in [2.1, 2.2, 2.4, 2.5]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible v2 of API",
        )


@pytest.fixture()
def test_skip_34(vc):
    if vc.version not in [3.4]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible v3.4+ of API",
        )


def test_get_user_generator(vc, test_skip):
    user_gen = vc.get_all_users()
    results = next(user_gen)

    assert len(results.json()["results"]) >= 1
    assert results.json()["count"] >= 1


def test_user_threaded(vc, test_skip):
    count = next(vc.get_all_users()).json()["count"]
    vc.threads = 8
    user_gen = []
    for results in vc.get_all_users():
        user_gen = user_gen + results.json()["results"]

    # assert len(results.json()["results"]) == 1
    assert count <= len(user_gen)
    vc.threads = 1


def test_get_user_by_name_v2(vc, test_skip_2):
    user = next(vc.get_all_users()).json()["results"][0]
    username = user["username"]
    resp = vc.get_user_by_name(username=username)

    assert resp.json()["results"][0]["username"] == username


def test_get_user_by_name_v3(vc, test_skip_34):
    user = next(vc.get_all_users()).json()["results"][0]
    username = user["name"]
    resp = vc.get_user_by_name(username=username)

    assert resp["name"] == username


def test_get_user_by_email_v3(vc, test_skip_34):
    user = next(vc.get_all_users()).json()["results"][0]
    email = user["email"]
    resp = vc.get_user_by_email(email=email)

    assert resp.json()["results"][0]["email"] == email


def test_get_user_by_id(vc):
    user = next(vc.get_all_users()).json()["results"][0]
    user_id = user["id"]
    resp = vc.get_user_by_id(user_id=user_id)

    assert resp.json()["id"] == user_id


def test_update_user_v2(vc, test_skip_2):
    resp = vc.get_user_by_name(username="API-test")
    print(resp)
    user_id = resp.json()["results"][0]["id"]
    resp = vc.update_user(
        user_id=user_id, account_type="local", authentication_profile=None
    )

    assert resp.json()["id"] == user_id


def test_get_user_roles(vc, test_skip_34):
    resp = vc.get_user_roles().json()

    assert len(resp) >= 8


@pytest.mark.dependency()
def test_create_user(vc, test_skip_34):
    resp = vc.create_user(
        name="API Test",
        role="security_analyst",
        email="testuser@test.com",
    )

    assert resp.status_code == 200


@pytest.mark.dependency(depends=["test_create_user"])
def test_update_user_v3(vc, test_skip_34):
    resp = vc.get_user_by_email(email="testuser@test.com").json()["results"][0]

    username = "USER TEST"
    resp = vc.update_user(user_id=resp["id"], name=username, role="read_only")

    resp = vc.get_user_by_email(email="testuser@test.com").json()["results"][0]

    assert resp["name"] == username
    assert resp["role"] == "read_only"


@pytest.mark.dependency(depends=["test_create_user"])
def test_delete_user(vc, test_skip_34):
    resp = vc.get_user_by_email(email="testuser@test.com").json()["results"][0]
    user_id = resp["id"]

    resp = vc.delete_user(user_id=user_id)

    assert resp.status_code == 204
