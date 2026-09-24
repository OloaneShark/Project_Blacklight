# Kubernetes Manifest Scanning

Project Blacklight statically scans Kubernetes workload YAML without connecting to a cluster.

Run:

```bash
blacklight scan kubernetes --path .
```

The short alias also works:

```bash
blacklight scan k8s --path .
```

Blacklight recursively reads `.yaml` and `.yml` files and evaluates workload pod specs for Pods, Deployments, StatefulSets, DaemonSets, ReplicaSets, ReplicationControllers, Jobs, CronJobs, and Kubernetes List items.

## Current deterministic checks

- `kubernetes.manifest.privileged_container` — CRITICAL when a container explicitly sets `privileged: true`.
- `kubernetes.manifest.root_user` — HIGH when the pod or a container explicitly sets `runAsUser: 0`.
- `kubernetes.manifest.privilege_escalation` — HIGH when a container explicitly sets `allowPrivilegeEscalation: true`.
- `kubernetes.manifest.host_namespace` — HIGH for explicit `hostNetwork`, `hostPID`, or `hostIPC`.
- `kubernetes.manifest.host_path` — HIGH when a workload uses a `hostPath` volume.
- `kubernetes.manifest.capabilities_all` — HIGH when a container adds Linux capability `ALL`.
- `kubernetes.manifest.seccomp_unconfined` — HIGH for explicit `seccompProfile.type: Unconfined`.
- `kubernetes.manifest.host_port` — MEDIUM when a container explicitly binds `hostPort`.
- `kubernetes.manifest.image_latest` — MEDIUM for implicit or `:latest` image tags.
- `kubernetes.manifest.literal_secret_env` — HIGH when a secret-like environment variable uses a literal value. Blacklight records the variable name but never the value.

## Static-analysis boundary

Blacklight does not infer runtime facts that the YAML cannot prove.

For example, absence of `runAsUser` is not automatically reported as "running as root" because admission policy, image metadata, or runtime defaults may change the effective UID.

This scanner does not currently:

- connect to the Kubernetes API
- inspect live Pods or Nodes
- read cluster RBAC
- inspect NetworkPolicies
- query admission controllers
- scan container package CVEs
- mutate manifests

Those are future extensions, not hidden assumptions in the current findings.

## CI example

```yaml
- name: Scan Kubernetes manifests
  run: blacklight scan kubernetes --path . --fail-on high --require-full-coverage
```

## Reports

Kubernetes scans use the same Blacklight reporting pipeline as AWS and Docker:

```bash
blacklight scan kubernetes --path . --format json --output reports/k8s.json
blacklight scan kubernetes --path . --format html --output reports/k8s.html
```

Risk scoring, coverage, severity gates, and report formats remain provider-independent.
