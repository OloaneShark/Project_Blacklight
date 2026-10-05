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


def test_builtin_server_scanner_is_registered():
    assert scanner_names("server") == ["accounts", "auth", "baseline", "hardening", "network", "packages", "services", "tls"]

    specs = scanner_specs("server", "baseline")
    assert len(specs) == 1
    assert specs[0].provider == "server"
    assert specs[0].name == "baseline"


def test_registry_selects_server_network_scanner():
    specs = scanner_specs("server", "network")
    assert len(specs) == 1
    assert specs[0].provider == "server"
    assert specs[0].name == "network"


def test_registry_selects_server_hardening_scanner():
    specs = scanner_specs("server", "hardening")
    assert len(specs) == 1
    assert specs[0].provider == "server"
    assert specs[0].name == "hardening"


def test_registry_selects_server_accounts_scanner():
    specs = scanner_specs("server", "accounts")
    assert len(specs) == 1
    assert specs[0].provider == "server"
    assert specs[0].name == "accounts"


def test_registry_selects_server_auth_scanner():
    specs = scanner_specs("server", "auth")
    assert len(specs) == 1
    assert specs[0].provider == "server"
    assert specs[0].name == "auth"


def test_registry_selects_server_packages_scanner():
    specs = scanner_specs("server", "packages")
    assert len(specs) == 1
    assert specs[0].provider == "server"
    assert specs[0].name == "packages"


def test_registry_selects_server_services_scanner():
    specs = scanner_specs("server", "services")
    assert len(specs) == 1
    assert specs[0].provider == "server"
    assert specs[0].name == "services"


def test_registry_selects_server_tls_scanner():
    specs = scanner_specs("server", "tls")
    assert len(specs) == 1
    assert specs[0].provider == "server"
    assert specs[0].name == "tls"
