# Blacklight Demo Fixtures

These files exist so the core scanner can be demonstrated without real infrastructure or credentials.

## Local-only fixtures

- `docker/secure/Dockerfile` — expected to produce no actionable static Docker findings.
- `docker/insecure/Dockerfile` — intentionally triggers multiple Dockerfile findings using fake placeholder values.
- `kubernetes/secure.yaml` — expected to produce no actionable static Kubernetes findings.
- `kubernetes/insecure.yaml` — intentionally triggers multiple workload-security findings.

Run the complete credential-free verification:

```bash
python scripts/verify_demo.py
```

## Online SBOM fixture

`sbom/vulnerable.cdx.json` is an intentionally old package example for the OSV-backed scanner.

```bash
blacklight scan docker --service sbom --path examples/demo/sbom/vulnerable.cdx.json
```

This command requires network access to OSV.dev. Package coordinates from the fixture are sent to OSV; no source code or real secret is included.

All secret-like strings in the demo fixtures are fake placeholders.
