import pytest
import requests

requests.packages.urllib3.disable_warnings()


if not pytest.config.getoption('--token'):
    pytest.skip('v1 client not configured', allow_module_level=True)


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


def test_detection_tags(vc_v2):
    detection = vc_v2.get_detections().json()['results'][0]
    detection_id = detection['id']
    detection_tags = detection['tags']

    vc_v2.set_detection_tags(detection_id=detection_id, tags=['pytest'])
    assert vc_v2.get_detection_tags(detection_id=detection_id).json()['tags'] == ['pytest']

    vc_v2.set_detection_tags(detection_id=detection_id, tags=['foo', 'bar'], append=True)
    assert vc_v2.get_detection_tags(detection_id=detection_id).json()['tags'] == ['pytest', 'foo', 'bar']

    vc_v2.set_detection_tags(detection_id=detection_id, tags=detection_tags)
    assert vc_v2.get_detection_tags(detection_id=detection_id).json()['tags'] == detection_tags


def test_get_detections_note_modified_apiv2(vc_v2):
    resp = vc_v2.get_detections(note_modified_timestamp_gte=1000)

    assert vc_v2.version == 2
    assert resp.status_code == 200


def test_mark_detections_as_fixed(vc_v2):
    resp = vc_v2.get_detections()
    assert resp.status_code == 200
    det_ids = [d['id'] for d in resp.json()['results']]

    assert vc_v2.mark_detections_fixed(detection_ids=det_ids).status_code == 200
    resp = vc_v2.get_detections()
    assert resp.status_code == 200
    assert all([d['state'] == 'fixed' for d in resp.json()['results']])

    assert vc_v2.unmark_detections_fixed(detection_ids=det_ids).status_code == 200
    resp = vc_v2.get_detections()
    assert resp.status_code == 200
    results = resp.json()['results']
    assert not any([d['state'] == 'fixed' for d in resp.json()['results']])
