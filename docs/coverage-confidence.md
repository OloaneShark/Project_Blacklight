# Scan Coverage and Risk Confidence

Project Blacklight keeps **security risk** and **scan coverage** separate.

A scanner error does not prove that a resource is insecure, so `ERROR` findings do not add security-risk points. At the same time, a low observed risk score should not look fully trustworthy when Blacklight could not inspect part of the selected scope.

## Coverage states

Blacklight evaluates coverage at the scanner level.

- `FULL`: every selected scanner completed without `ERROR` findings.
- `PARTIAL`: at least one selected scanner completed without errors and at least one selected scanner returned one or more `ERROR` findings.
- `LIMITED`: every selected scanner returned one or more `ERROR` findings.
- `UNKNOWN`: no scanners were executed.

A scanner is considered fully evaluated only when it returns no `ERROR` findings. This is intentionally conservative: one inspection error is enough to mark that scanner as affected even if some of its other checks completed successfully.

## Risk confidence

Coverage maps to a simple confidence label:

| Coverage | Risk confidence | Meaning |
| --- | --- | --- |
| `FULL` | `HIGH` | The observed risk score covers every selected scanner without inspection errors. |
| `PARTIAL` | `REDUCED` | Some selected services were not fully inspected, so the observed risk score may understate actual risk. |
| `LIMITED` | `LOW` | Every selected scanner had inspection errors; the observed score should not be treated as a complete assessment. |
| `UNKNOWN` | `UNKNOWN` | No scanner coverage was available to evaluate. |

These labels are deterministic completeness labels, not statistical probabilities.

## Exit-code behavior

Blacklight still distinguishes security-policy failures from operational coverage failures:

```text
0 = scan completed enough to produce a usable assessment and any requested security gate passed
1 = the requested `--fail-on` security threshold was reached or exceeded
2 = Blacklight could not complete a usable scan, including the case where every selected scanner failed
```

A `PARTIAL` scan can still return `0` when no security gate fails because the completed scanners may provide useful evidence. The report explicitly marks the reduced confidence and lists the affected scanners.

A `LIMITED` scan returns exit code `2` after the report is rendered or written, so CI/CD systems do not treat a completely failed inspection as a successful security assessment.

## Provider API failures

If an individual AWS scanner raises an AWS `ClientError`, the scan runner converts that failure into a normalized `ERROR` finding for that scanner and continues with the remaining selected scanners. This allows Blacklight to report partial coverage instead of discarding evidence collected by healthy scanners.

Credential-loading failures and other top-level operational failures still stop the scan and return exit code `2`.

## JSON

Scan metadata includes a `coverage` object similar to:

```json
{
  "status": "PARTIAL",
  "risk_confidence": "REDUCED",
  "scanner_count": 7,
  "complete_scanner_count": 6,
  "affected_scanner_count": 1,
  "complete_scanner_percent": 85.7,
  "error_finding_count": 2,
  "affected_scanners": ["iam"],
  "message": "One or more selected scanners returned ERROR findings..."
}
```

The risk score remains based only on deterministic security findings. Coverage never adds risk points by itself.
