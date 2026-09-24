# Optional Analyst Integrations

Project Blacklight security detection remains deterministic.

The optional analyst interface exists only to let another program explain or summarize a **completed Blacklight JSON report**. It does not run scanners, change severity, remove findings, change CI/CD exit codes, or decide whether a security condition exists.

## Generate a report

```bash
blacklight scan aws --format json --output reports/aws.json
blacklight scan docker --path . --format json --output reports/docker.json
blacklight scan kubernetes --path . --format json --output reports/kubernetes.json
```

## Run an external analyst

```bash
blacklight analyze \
  --input reports/aws.json \
  --command python \
  --arg my_analyst.py
```

Blacklight sends the complete report JSON to the analyst command on standard input.

The analyst writes its explanation to standard output.

To save the result:

```bash
blacklight analyze \
  --input reports/aws.json \
  --command python \
  --arg my_analyst.py \
  --output reports/aws-analysis.txt
```

## Minimal analyst example

```python
import json
import sys

report = json.load(sys.stdin)

risk = report["risk"]
findings = report["findings"]

print(f"Observed risk: {risk['level']} ({risk['score']}/100)")
for finding in findings:
    if finding["severity"] not in {"PASS", "INFO"}:
        print(f"- {finding['severity']}: {finding['title']}")
```

That example contains no AI at all. A user can replace its internals with a local LLM client or an API client.

## Security boundary

Blacklight launches analyst commands with:

- an argument vector, not a shell command string
- `shell=False`
- JSON through stdin rather than command-line arguments
- a configurable timeout capped at 10 minutes

Blacklight does **not** automatically discover or execute analyst programs.

The user must explicitly provide `--command`.

The analyst inherits the local process environment. If an analyst uses an API key, that key belongs to the analyst program and is never stored in a Blacklight finding or report.

## Detection remains authoritative

The flow is:

```text
provider/configuration evidence
        ↓
Blacklight deterministic scanners
        ↓
normalized findings
        ↓
risk + coverage + CI gates
        ↓
saved JSON report
        ↓
optional external analyst
        ↓
human-readable explanation
```

Only the deterministic side controls Blacklight security findings and exit codes.

This design also keeps vendor-specific AI SDKs out of the core Blacklight dependency tree.
