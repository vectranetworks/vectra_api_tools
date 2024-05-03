import pytest
import requests

requests.packages.urllib3.disable_warnings()


def test_detection_generator(vc):
    det_gen = vc.get_all_detections(page_size=1)
    results = next(det_gen)

    assert len(results.json()["results"]) == 1
    assert results.json()["count"] > 1


def test_detection_id(vc):
    det_id = next(vc.get_all_detections()).json()["results"][0]["id"]
    result = vc.get_detection_by_id(detection_id=det_id)

    assert result.json()["id"] == det_id


def test_detection_tags(vc):
    detection = next(vc.get_all_detections()).json()["results"][0]
    detection_id = detection["id"]
    detection_tags = detection["tags"]

    vc.set_detection_tags(detection_id=detection_id, tags=["pytest"])
    assert vc.get_detection_tags(detection_id=detection_id).json()["tags"] == ["pytest"]

    vc.set_detection_tags(detection_id=detection_id, tags=["foo", "bar"], append=True)
    assert vc.get_detection_tags(detection_id=detection_id).json()["tags"] == [
        "pytest",
        "foo",
        "bar",
    ]

    vc.set_detection_tags(detection_id=detection_id, tags=detection_tags)
    assert (
        vc.get_detection_tags(detection_id=detection_id).json()["tags"]
        == detection_tags
    )


def test_get_detections_note_modified_apiv2(vc):
    resp = next(vc.get_all_detections(note_modified_timestamp_gte=1000))

    assert resp.status_code == 200


def test_mark_detections_as_fixed(vc):
    resp = next(vc.get_all_detections())
    assert resp.status_code == 200
    det_ids = [d["id"] for d in resp.json()["results"]]

    assert vc.mark_detections_fixed(detection_ids=det_ids).status_code == 200
    resp = next(vc.get_all_detections())
    assert resp.status_code == 200
    assert all([d["state"] == "fixed" for d in resp.json()["results"]])

    assert vc.unmark_detections_fixed(detection_ids=det_ids).status_code == 200
    resp = next(vc.get_all_detections())
    assert resp.status_code == 200
    assert not any([d["state"] == "fixed" for d in resp.json()["results"]])
