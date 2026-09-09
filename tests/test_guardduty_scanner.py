from blacklight_security.models import Severity
from blacklight_security.scanners.aws import GuardDutyScanner


class FakeSession:
    region_name = "us-east-1"

    def __init__(self, client):
        self._client = client

    def client(self, service_name):
        assert service_name == "guardduty"
        return self._client


class NoDetectorGuardDuty:
    def list_detectors(self):
        return {"DetectorIds": []}


class EnabledGuardDuty:
    def list_detectors(self):
        return {"DetectorIds": ["detector-123"]}

    def get_detector(self, DetectorId):
        assert DetectorId == "detector-123"
        return {"Status": "ENABLED"}


def test_guardduty_scanner_flags_region_without_detector():
    findings = GuardDutyScanner(FakeSession(NoDetectorGuardDuty())).scan()

    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].resource_id == "us-east-1"


def test_guardduty_scanner_passes_enabled_detector():
    findings = GuardDutyScanner(FakeSession(EnabledGuardDuty())).scan()

    assert len(findings) == 1
    assert findings[0].severity is Severity.PASS
    assert findings[0].resource_id == "detector-123"
