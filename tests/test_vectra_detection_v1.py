import pytest
import requests

requests.packages.urllib3.disable_warnings()


if not pytest.config.getoption('--user'):
    pytest.skip('v1 client not configured', allow_module_level=True)


def test_get_detections(vc_v1):
    resp = vc_v1.get_detections()

    assert vc_v1.version == 1
    assert resp.status_code == 200


def test_detection_generator(vc_v1):
    det_gen = vc_v1.get_all_detections(page_size=1)
    results = next(det_gen)

    assert len(results.json()['results']) == 1
    assert results.json()['count'] > 1


def test_detection_id(vc_v1):
    det_id = vc_v1.get_detections().json()['results'][0]['id']
    result = vc_v1.get_detection_by_id(detection_id=det_id)

    assert result.json()['id'] == det_id