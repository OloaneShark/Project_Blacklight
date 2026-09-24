from pathlib import Path

from blacklight_security.models import Severity
from blacklight_security.scanners.kubernetes import (
    KubernetesManifestScanner,
    KubernetesScanTarget,
)


def _scan(tmp_path: Path, content: str):
    manifest = tmp_path / "deployment.yaml"
    manifest.write_text(content, encoding="utf-8")
    return KubernetesManifestScanner(KubernetesScanTarget(tmp_path)).scan()


def _by_check(findings):
    return {finding.check_id: finding for finding in findings}


def test_secure_deployment_passes_high_signal_checks(tmp_path):
    findings = _scan(
        tmp_path,
        """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
spec:
  template:
    metadata:
      labels:
        app: api
    spec:
      securityContext:
        runAsUser: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: api
          image: ghcr.io/example/api:1.2.3
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            runAsUser: 1000
            capabilities:
              drop: ["ALL"]
""".strip(),
    )

    checks = _by_check(findings)

    assert checks["kubernetes.manifest.privileged_container"].severity is Severity.PASS
    assert checks["kubernetes.manifest.root_user"].severity is Severity.PASS
    assert checks["kubernetes.manifest.privilege_escalation"].severity is Severity.PASS
    assert checks["kubernetes.manifest.host_namespace"].severity is Severity.PASS
    assert checks["kubernetes.manifest.host_path"].severity is Severity.PASS
    assert checks["kubernetes.manifest.capabilities_all"].severity is Severity.PASS
    assert checks["kubernetes.manifest.seccomp_unconfined"].severity is Severity.PASS
    assert checks["kubernetes.manifest.host_port"].severity is Severity.PASS
    assert checks["kubernetes.manifest.image_latest"].severity is Severity.PASS
    assert checks["kubernetes.manifest.literal_secret_env"].severity is Severity.PASS


def test_dangerous_pod_settings_are_reported(tmp_path):
    findings = _scan(
        tmp_path,
        """
apiVersion: v1
kind: Pod
metadata:
  name: dangerous
spec:
  hostNetwork: true
  hostPID: true
  volumes:
    - name: host-root
      hostPath:
        path: /
  containers:
    - name: app
      image: alpine:latest
      env:
        - name: API_TOKEN
          value: super-secret-value
      ports:
        - containerPort: 8080
          hostPort: 8080
      securityContext:
        privileged: true
        allowPrivilegeEscalation: true
        runAsUser: 0
        seccompProfile:
          type: Unconfined
        capabilities:
          add: ["ALL"]
""".strip(),
    )

    checks = _by_check(findings)

    assert checks["kubernetes.manifest.privileged_container"].severity is Severity.CRITICAL
    assert checks["kubernetes.manifest.root_user"].severity is Severity.HIGH
    assert checks["kubernetes.manifest.privilege_escalation"].severity is Severity.HIGH
    assert checks["kubernetes.manifest.host_namespace"].severity is Severity.HIGH
    assert checks["kubernetes.manifest.host_path"].severity is Severity.HIGH
    assert checks["kubernetes.manifest.capabilities_all"].severity is Severity.HIGH
    assert checks["kubernetes.manifest.seccomp_unconfined"].severity is Severity.HIGH
    assert checks["kubernetes.manifest.host_port"].severity is Severity.MEDIUM
    assert checks["kubernetes.manifest.image_latest"].severity is Severity.MEDIUM

    secret = checks["kubernetes.manifest.literal_secret_env"]
    assert secret.severity is Severity.HIGH
    assert secret.evidence["secret_values_redacted"] is True
    assert "super-secret-value" not in str(secret.evidence)


def test_digest_pinned_image_avoids_latest_finding(tmp_path):
    findings = _scan(
        tmp_path,
        """
apiVersion: v1
kind: Pod
metadata:
  name: digest
spec:
  containers:
    - name: app
      image: ghcr.io/example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
""".strip(),
    )

    assert _by_check(findings)["kubernetes.manifest.image_latest"].severity is Severity.PASS


def test_cronjob_pod_template_is_scanned(tmp_path):
    findings = _scan(
        tmp_path,
        """
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup
spec:
  schedule: "0 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: backup
              image: example/backup
              securityContext:
                runAsUser: 0
""".strip(),
    )

    checks = _by_check(findings)
    assert checks["kubernetes.manifest.root_user"].severity is Severity.HIGH
    assert checks["kubernetes.manifest.image_latest"].severity is Severity.MEDIUM


def test_kubernetes_list_items_are_expanded(tmp_path):
    findings = _scan(
        tmp_path,
        """
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Pod
    metadata:
      name: one
    spec:
      containers:
        - name: app
          image: alpine:3.21
  - apiVersion: v1
    kind: Pod
    metadata:
      name: two
    spec:
      containers:
        - name: app
          image: alpine:3.21
          securityContext:
            privileged: true
""".strip(),
    )

    resources = {finding.resource_id for finding in findings}
    assert "Pod/default/one" in resources
    assert "Pod/default/two" in resources

    critical = [
        finding
        for finding in findings
        if finding.check_id == "kubernetes.manifest.privileged_container"
        and finding.severity is Severity.CRITICAL
    ]
    assert len(critical) == 1
    assert critical[0].resource_id == "Pod/default/two"


def test_malformed_yaml_returns_error(tmp_path):
    findings = _scan(tmp_path, "kind: Pod\nspec: [not: valid")

    assert len(findings) == 1
    assert findings[0].check_id == "kubernetes.manifest.parse"
    assert findings[0].severity is Severity.ERROR


def test_missing_yaml_returns_error(tmp_path):
    findings = KubernetesManifestScanner(KubernetesScanTarget(tmp_path)).scan()

    assert len(findings) == 1
    assert findings[0].check_id == "kubernetes.manifest.discovery"
    assert findings[0].severity is Severity.ERROR


def test_non_workload_yaml_is_ignored_without_false_security_findings(tmp_path):
    findings = _scan(
        tmp_path,
        """
apiVersion: v1
kind: ConfigMap
metadata:
  name: config
data:
  mode: production
""".strip(),
    )

    assert findings == []
