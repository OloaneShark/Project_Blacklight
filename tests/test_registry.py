from blacklight_security.registry import scanner_names, scanner_specs


def test_builtin_aws_scanners_are_registered():
    assert scanner_names("aws") == [
        "cloudtrail",
        "ec2",
        "guardduty",
        "iam",
        "lambda",
        "rds",
        "s3",
    ]


def test_registry_selects_one_scanner():
    specs = scanner_specs("aws", "s3")
    assert len(specs) == 1
    assert specs[0].provider == "aws"
    assert specs[0].name == "s3"


def test_builtin_docker_scanner_is_registered():
    assert scanner_names("docker") == ["dockerfile"]

    specs = scanner_specs("docker", "dockerfile")
    assert len(specs) == 1
    assert specs[0].provider == "docker"
    assert specs[0].name == "dockerfile"


def test_builtin_kubernetes_scanner_is_registered():
    assert scanner_names("kubernetes") == ["manifest"]

    specs = scanner_specs("kubernetes", "manifest")
    assert len(specs) == 1
    assert specs[0].provider == "kubernetes"
    assert specs[0].name == "manifest"
