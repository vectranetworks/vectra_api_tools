import pytest
import requests

requests.packages.urllib3.disable_warnings()


def test_account_generator(vc):
    account_gen = vc.get_all_accounts(page_size=1)
    results = next(account_gen)

    assert len(results.json()["results"]) == 1
    assert results.json()["count"] >= 1


def test_accounts_threaded(vc):
    count = next(vc.get_all_accounts(page_size=1)).json()["count"]
    vc.threads = 8
    account_gen = []
    for results in vc.get_all_accounts(page_size=50):
        account_gen = account_gen + results.json()["results"]

    assert count == len(account_gen)
    vc.threads = 1


def test_get_accounts_id(vc):
    account_id = next(vc.get_all_accounts()).json()["results"][0]["id"]
    resp = vc.get_account_by_id(account_id=account_id)

    assert resp.json()["id"] == account_id


def test_account_tags(vc):
    account = next(vc.get_all_accounts()).json()["results"][0]
    account_id = account["id"]
    account_tags = account["tags"]

    vc.set_account_tags(account_id=account_id, tags=["pytest"])
    assert vc.get_account_tags(account_id=account_id).json()["tags"] == ["pytest"]

    vc.set_account_tags(account_id=account_id, tags=["foo", "bar"], append=True)
    assert vc.get_account_tags(account_id=account_id).json()["tags"] == [
        "pytest",
        "foo",
        "bar",
    ]

    vc.set_account_tags(account_id=account_id, tags=account_tags)
    assert vc.get_account_tags(account_id=account_id).json()["tags"].sort() == account_tags.sort()
