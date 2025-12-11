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
    ctx = snapshot.to_detect_context(http_client="client")
    assert ctx["react_major_confidence"] == "high"
    assert ctx["server_action_endpoints"] == ["/RSC/F/abc/action.txt"]


def test_detection_snapshot_falls_back_to_versions():
    detection = FrameworkDetectionResult(tags=[], signals={"detected_react_version": "19.1.0"})
    snapshot = DetectionSnapshot.from_detection(detection)
    assert snapshot.react_major == 19
