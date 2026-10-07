# Kubernetes Security Scanning

Project Blacklight supports both static Kubernetes workload-manifest analysis and explicit read-only inspection of a live cluster through kubectl. Static manifest scanning remains the default.

Run:

```bash
blacklight scan kubernetes --path .
```

The short alias also works:

```bash
blacklight scan k8s --path .
```

Inspect the current live kubectl context:

```bash
blacklight scan kubernetes --service cluster
```

Inspect an explicit kubectl context:

```bash
blacklight scan kubernetes --service cluster --context production
```

Inspect live RBAC grants:

```bash
blacklight scan kubernetes --service rbac --context production
```

Run both manifest and live-cluster scanners:

```bash
blacklight scan kubernetes --service all --path .
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

## Live cluster checks

The `cluster` scanner uses the local `kubectl` CLI with argument-list subprocess calls, bounded timeouts, and `shell=False`. It performs only read operations.

Blacklight requests all live Pods and reuses the same deterministic workload checks as the manifest scanner, but reports them with `kubernetes.cluster.*` IDs against the admitted live Pod specs. This means findings such as privileged mode, UID 0, host namespaces, hostPath, ALL capabilities, Unconfined seccomp, hostPort, mutable image tags, and literal secret-like environment values are based on what the API currently reports for running/created Pods.

The scanner also inventories Services with NodePort, LoadBalancer, externalIPs, or load-balancer ingress as LOW exposure findings. That proves cluster-level exposure configuration only; it does not prove public internet reachability or exploitability.

If Pod inventory succeeds but Service listing is forbidden, Blacklight keeps the Pod findings and records the Service permission failure as an ERROR coverage gap.

The live scanner never creates, patches, deletes, execs into, or otherwise mutates Kubernetes resources.

## Live RBAC checks

The `rbac` scanner reads live Roles, ClusterRoles, RoleBindings, and ClusterRoleBindings, resolves each binding back to its referenced role, and reports dangerous permissions only when they are actually granted to subjects.

Current deterministic RBAC checks include:

- wildcard verbs plus wildcard resources on a bound role — HIGH
- read access to Secrets through get/list/watch or wildcard verbs — HIGH
- create/wildcard access to `pods/exec` — HIGH
- Kubernetes identity impersonation grants — HIGH
- `cluster-admin` bound to `system:anonymous` or `system:unauthenticated` — CRITICAL
- `cluster-admin` bound to `system:authenticated` — HIGH
- other explicit `cluster-admin` bindings — INFO privilege inventory

Blacklight does not flag an unused powerful Role or ClusterRole merely because it exists. The role must be referenced by a live binding for the bound-permission checks to fire.

If the audit identity cannot list one of the RBAC resource types, Blacklight records an ERROR coverage gap rather than assuming no dangerous grants exist.

## Static-analysis boundary

Blacklight does not infer runtime facts that the YAML cannot prove.

For example, absence of `runAsUser` is not automatically reported as "running as root" because admission policy, image metadata, or runtime defaults may change the effective UID.

Blacklight still does **not** yet:

- inspect node configuration directly
- calculate transitive/effective RBAC privilege graphs beyond directly resolved live bindings
- inspect NetworkPolicy enforcement semantics
- query admission-controller configuration
- scan container package CVEs
- mutate manifests or live resources

Those remain future extensions rather than hidden assumptions in current findings.

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
