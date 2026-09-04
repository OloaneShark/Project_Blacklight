from blacklight_security.registry import scanner_names, scanner_specs


def test_builtin_aws_scanners_are_registered():
    assert scanner_names("aws") == ["cloudtrail", "ec2", "iam", "rds", "s3"]


def test_registry_selects_one_scanner():
    specs = scanner_specs("aws", "s3")
    assert len(specs) == 1
    assert specs[0].provider == "aws"
    assert specs[0].name == "s3"
