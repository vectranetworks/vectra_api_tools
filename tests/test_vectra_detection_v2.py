import requests

requests.packages.urllib3.disable_warnings()


def test_get_detections_apiv2(vc_v2):
    resp = vc_v2.get_detections()

    assert vc_v2.version == 2
    assert resp.status_code == 200


def test_detection_generator_apiv2(vc_v2):
    det_gen = vc_v2.get_all_detections(page_size=1)
    results = next(det_gen)

    assert len(results.json()['results']) == 1
    assert results.json()['count'] > 1


def test_detection_id(vc_v2):
    det_id = vc_v2.get_detections().json()['results'][0]['id']
    result = vc_v2.get_detection_by_id(detection_id=det_id)

    assert result.json()['id'] == det_id