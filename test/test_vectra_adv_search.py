import pytest
import requests

requests.packages.urllib3.disable_warnings()


@pytest.fixture()
def test_skip(vc):
    if vc.version not in [2.1, 2.2, 2.4, 2.5]:
        pytest.skip(
            allow_module_level=True,
            reason="Method is accessible via v2 of API",
        )


def test_critical_quad_host_count(vc, test_skip):
    basic_count = next(vc.get_all_hosts(certainty_gte=50, threat_gte=50)).json()[
        "count"
    ]

    adv_count = len(
        next(
            vc.advanced_search(
                stype="hosts", query="host.certainty:>=50 and host.threat:>=50"
            )
        ).json()["results"]
    )

    assert adv_count == basic_count


def test_ip_search(vc, test_skip):
    test_ip = next(vc.get_all_hosts()).json()["results"][-1]["last_source"]

    basic_host = next(vc.get_all_hosts(last_source=test_ip)).json()["results"][0]

    adv_host = next(
        vc.advanced_search(
            stype="hosts", query="host.last_source:{ip}".format(ip=test_ip)
        )
    ).json()["results"][0]

    assert adv_host["id"] == basic_host["id"]


def test_page_size(vc, test_skip):
    ret_objects = len(
        next(
            vc.advanced_search(
                stype="hosts", query='host.state:"active" OR host.state:"inactive"'
            )
        ).json()["results"]
    )
    assert ret_objects == 50

    ret_objects = len(
        next(
            vc.advanced_search(
                stype="hosts",
                page_size=100,
                query='host.state:"active" OR host.state:"inactive"',
            )
        ).json()["results"]
    )
    assert ret_objects == 100

    ret_objects = len(
        next(
            vc.advanced_search(
                stype="hosts",
                page_size=17,
                query='host.state:"active" OR host.state:"inactive"',
            )
        ).json()["results"]
    )
    assert ret_objects == 17


def test_medium_and_critical_detection_count(vc, test_skip):
    basic_count = next(vc.get_all_detections(certainty_gte=50)).json()["count"]
    adv_count = len(
        next(
            vc.advanced_search(
                stype="detections", page_size=5000, query="detection.certainty:>=50"
            )
        ).json()["results"]
    )

    # basic search returns triaged detections
    assert adv_count <= basic_count
