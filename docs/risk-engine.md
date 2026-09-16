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
