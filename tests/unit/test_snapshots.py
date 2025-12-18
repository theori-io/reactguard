from reactguard.models import FrameworkDetectionResult
from reactguard.vulnerability_detection.snapshots import DetectionSnapshot


def test_detection_snapshot_resolves_versions_and_context():
    detection = FrameworkDetectionResult(
        tags=["nextjs"],
        signals={
            "detected_react_major": "19",
            "detected_react_major_confidence": "high",
            "server_actions_enabled": True,
            "server_actions_confidence": "medium",
            "server_action_endpoints": ["/RSC/F/abc/action.txt"],
        },
    )
    snapshot = DetectionSnapshot.from_detection(detection)
    assert snapshot.react_major == 19
    ctx = snapshot.to_detect_context()
    assert ctx["react_major_confidence"] == "high"
    assert ctx["server_action_endpoints"] == ["/RSC/F/abc/action.txt"]


def test_detection_snapshot_falls_back_to_versions():
    detection = FrameworkDetectionResult(tags=[], signals={"detected_react_version": "19.1.0"})
    snapshot = DetectionSnapshot.from_detection(detection)
    assert snapshot.react_major == 19


def test_detection_snapshot_prefers_rsc_runtime_version_for_react_major():
    detection = FrameworkDetectionResult(
        tags=[],
        signals={
            "detected_react_version": "18.2.0",
            "detected_rsc_runtime_version": "19.0.0",
            "detected_rsc_runtime_version_confidence": "high",
        },
    )
    snapshot = DetectionSnapshot.from_detection(detection)
    assert snapshot.react_major == 19
    assert snapshot.react_major_confidence == "high"
