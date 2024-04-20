import pytest
import requests

requests.packages.urllib3.disable_warnings()

test_vars = {}


@pytest.fixture()
def test_skip(vc):
    if vc.version not in [2.1, 2.2, 2.4, 2.5, 3.3]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible via v2 and v3.3+ of API",
        )


@pytest.fixture()
def test_host(vc):
    return next(vc.get_all_hosts()).json()["results"][-1]


@pytest.fixture()
def test_host2(vc):
    return next(vc.get_all_hosts()).json()["results"][-2]


def test_get_rules(vc):
    resp = next(vc.get_all_rules())
    assert resp.status_code == 200
    assert resp.json()["count"] >= 1


def test_create_rule_host(vc, test_skip, test_host):
    resp = vc.create_rule(
        detection_category="botnet activity",
        detection_type="cryptocurrency mining",
        triage_category="misconfiguration",
        description="pytest_host_rule",
        is_whitelist=False,
        additional_conditions={
            "OR": [
                {
                    "AND": [
                        {
                            "ANY_OF": {
                                "field": "remote1_ip",
                                "values": [{"value": "1.1.1.1"}],
                                "groups": [],
                            }
                        }
                    ]
                }
            ]
        },
        source_conditions={
            "OR": [
                {
                    "AND": [
                        {
                            "ANY_OF": {
                                "field": "host",
                                "values": [
                                    {"value": test_host["url"]},
                                ],
                                "groups": [],
                            }
                        }
                    ]
                }
            ]
        },
    )
    test_vars["host_rule_id"] = resp.json().get("id", None)
    assert resp.status_code == 201


def test_create_rule_ip(vc):
    resp = vc.create_rule(
        detection_category="botnet activity",
        detection_type="outbound dos",
        triage_category="misconfiguration",
        description="pytest_ip_rule",
        additional_conditions={
            "OR": [
                {
                    "AND": [
                        {
                            "ANY_OF": {
                                "field": "remote1_ip",
                                "values": [{"value": "1.1.1.1"}],
                                "groups": [],
                            }
                        }
                    ]
                }
            ]
        },
        source_conditions={
            "OR": [
                {
                    "AND": [
                        {
                            "ANY_OF": {
                                "field": "ip",
                                "values": [
                                    {"value": "1.1.1.1"},
                                    {"value": "1.2.1.1"},
                                    {"value": "1.1.3.1"},
                                ],
                                "groups": [],
                            }
                        }
                    ]
                }
            ]
        },
    )

    test_vars["host_rule_ip"] = resp.json().get("id", None)
    assert resp.status_code == 201


def test_update_rule_replace(vc):
    resp = vc.update_rule(
        rule_id=test_vars["host_rule_ip"],
        triage_category="Pytest Replace",
        description="pytest_ip_rule_replace",
        additional_conditions={
            "OR": [
                {
                    "AND": [
                        {
                            "ANY_OF": {
                                "field": "remote1_ip",
                                "values": [{"value": "2.2.2.2"}],
                                "groups": [],
                            }
                        }
                    ]
                }
            ]
        },
        source_conditions={
            "OR": [
                {
                    "AND": [
                        {
                            "ANY_OF": {
                                "field": "ip",
                                "values": [
                                    {"value": "2.2.2.2"},
                                    {"value": "2.2.1.1"},
                                    {"value": "2.1.3.1"},
                                ],
                                "groups": [],
                            }
                        }
                    ]
                }
            ]
        },
    )
    assert resp.status_code == 200
    # for value in resp.json()["source_conditions"]["OR"][0]["AND"][0]["ANY_OF"]["values"][0]:
    # assert "2.1.3.1"
    assert (
        "2.2.2.2"
        == resp.json()["data"]["additional_conditions"]["OR"][0]["AND"][0]["ANY_OF"][
            "values"
        ][0]["value"]
    )


def test_delete_rule(vc):
    if vc.version in [2.1, 2.2, 2.4, 2.5, 3.3]:
        resp1 = vc.delete_rule(rule_id=test_vars["host_rule_id"])
        assert resp1.status_code == 204
    resp2 = vc.delete_rule(rule_id=test_vars["host_rule_ip"])
    assert resp2.status_code == 204
