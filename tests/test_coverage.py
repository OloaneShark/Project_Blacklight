from blacklight_security.coverage import assess_coverage


def test_full_coverage_has_high_risk_confidence():
    coverage = assess_coverage(["s3", "iam", "ec2"], {})

    assert coverage.status == "FULL"
    assert coverage.risk_confidence == "HIGH"
    assert coverage.complete_scanner_count == 3
    assert coverage.affected_scanner_count == 0
    assert coverage.complete_scanner_percent == 100.0
    assert coverage.error_finding_count == 0


def test_partial_coverage_reduces_risk_confidence():
    coverage = assess_coverage(
        ["s3", "iam", "ec2", "rds"],
        {"iam": 2, "rds": 1},
    )

    assert coverage.status == "PARTIAL"
    assert coverage.risk_confidence == "REDUCED"
    assert coverage.complete_scanner_count == 2
    assert coverage.affected_scanner_count == 2
    assert coverage.complete_scanner_percent == 50.0
    assert coverage.error_finding_count == 3
    assert coverage.affected_scanners == ("iam", "rds")


def test_limited_coverage_has_low_risk_confidence():
    coverage = assess_coverage(["s3", "iam"], {"s3": 1, "iam": 4})

    assert coverage.status == "LIMITED"
    assert coverage.risk_confidence == "LOW"
    assert coverage.complete_scanner_count == 0
    assert coverage.complete_scanner_percent == 0.0
    assert coverage.error_finding_count == 5


def test_no_scanners_produces_unknown_coverage():
    coverage = assess_coverage([], {})

    assert coverage.status == "UNKNOWN"
    assert coverage.risk_confidence == "UNKNOWN"
    assert coverage.scanner_count == 0
