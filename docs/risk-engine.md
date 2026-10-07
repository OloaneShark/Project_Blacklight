# Project Blacklight Risk Engine

Project Blacklight keeps detection and risk scoring deterministic. Scanner findings are produced from provider APIs and explicit checks. The risk engine then combines those normalized findings using fixed severity weights and named correlation rules.

No AI model decides whether a finding exists or whether a correlation fires.

## Severity weights

| Severity | Points |
| --- | ---: |
| CRITICAL | 40 |
| HIGH | 20 |
| MEDIUM | 8 |
| LOW | 3 |
| PASS | 0 |
| INFO | 0 |
| ERROR | 0 |

The base score is the sum of actionable finding weights, capped at 100.

## Risk levels

| Score | Level |
| --- | --- |
| 80-100 | CRITICAL |
| 50-79 | HIGH |
| 25-49 | MEDIUM |
| 1-24 | LOW |
| 0 | CLEAR |

Correlation points are added after the base score and the final score is capped at 100.

## Current correlation rules

### `aws.rds.public_and_unencrypted` (+20)

Fires when the same RDS instance is both publicly accessible and missing storage encryption.

### `aws.s3.public_without_access_logging` (+10)

Fires when the same S3 bucket has a public bucket-policy finding and S3 server access logging is not enabled.

### `aws.s3.public_policy_without_full_public_access_block` (+15)

Fires when the same S3 bucket is public and bucket-level Block Public Access is not fully enabled.

### `aws.iam.broad_role_permissions_and_trust` (+20)

Fires when the same IAM role has both an unconditional wildcard identity-policy grant and an unconditional wildcard trust principal. The rule represents the combination of broad permissions and broad role-assumption trust; Blacklight still does not claim to calculate final effective permissions or every prerequisite for successful role assumption.

### `aws.critical_findings_with_cloudtrail_gap` (+15)

Fires when at least one non-CloudTrail CRITICAL finding exists while CloudTrail has a high-severity visibility gap. A visibility gap includes either no configured trail or a configured trail that is not actively logging.

### `aws.root_mfa_with_cloudtrail_gap` (+15)

Fires when root-user MFA is not enabled and CloudTrail also has a high-severity visibility gap.

### `aws.regional_public_exposure_with_guardduty_gap` (+15)

Fires when a regional EC2, RDS, or Lambda public-exposure finding exists while GuardDuty is not enabled in the scanned region.

S3 is intentionally excluded from this regional rule because S3 bucket discovery can span buckets outside the selected regional context.

## Same-resource matching

Rules that require two findings on the same resource group findings by:

```text
provider + service + resource ID
```

This prevents unrelated resources in different services from correlating merely because they share the same identifier text.

## Errors and incomplete coverage

`ERROR` findings do not currently add risk points. They represent checks Blacklight could not complete rather than proof that the underlying resource is insecure.

Scan status can still become `PARTIAL` when an `ERROR` finding exists, so reporting can distinguish confirmed security findings from incomplete inspection coverage.


## Linux server authentication correlation

Blacklight adds a deterministic server correlation when both of these findings occur on the same Linux server:

- `server.auth.empty_password_accounts`
- `server.auth.pam_null_passwords`

The correlation ID is `server.auth.empty_password_with_pam_nullok` and adds 20 risk points. It means Blacklight observed both an empty local password field and a PAM `pam_unix` authentication path explicitly configured with `nullok`. This increases risk but does not independently prove that a specific remote service will accept an empty password.


## Docker runtime correlations

### `docker.daemon.privileged_with_docker_socket` (+25)

Fires when the same running Docker container is both privileged and has a Docker daemon socket mount finding. This combines broad host capability with direct daemon-control exposure.

### `docker.daemon.privileged_with_nonloopback_publish` (+15)

Fires when the same privileged Docker container also publishes a port on non-loopback host interfaces. The correlation represents combined runtime privilege and host-network exposure; it does not claim internet reachability.

## Kubernetes live-cluster correlations

### `kubernetes.cluster.privileged_with_host_path` (+20)

Fires when the same live Pod contains a privileged container and also mounts a hostPath volume, combining broad runtime privilege with direct node-filesystem access.

### `kubernetes.cluster.privileged_with_host_port` (+15)

Fires when the same live Pod contains a privileged container and also configures hostPort, combining elevated container privilege with direct node-network exposure.

All four runtime rules use Blacklight's same-resource grouping. Findings on different containers or Pods do not correlate merely because they occur in the same scan.


### `docker.daemon.root_with_writable_sensitive_host_mount` (+20)

Fires when the same running Docker container is configured with the default/root user and also has a writable bind mount from one of Blacklight's selected sensitive host paths. Read-only sensitive mounts do not trigger this correlation.
