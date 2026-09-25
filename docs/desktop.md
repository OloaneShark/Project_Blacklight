# Project Blacklight Desktop

Project Blacklight Desktop is the graphical front end for the same deterministic scanning engine used by the `blacklight` CLI.

The first desktop release targets Windows and is packaged as a native one-file executable.

## User experience

The desktop layout follows the same broad pattern as modern local developer/security workspaces:

```text
BLACKLIGHT
├── Dashboard
├── Scan
├── Findings
├── Reports
└── Settings
```

The Dashboard exposes target cards for:

- AWS Account
- Docker Project
- Kubernetes Manifests
- Server / SSH (visible as the next product phase, not falsely enabled)

The UI is intentionally dark, sharp-edged, local-first, and focused on evidence rather than decorative dashboard widgets.

## Run a scan

### AWS

Choose **AWS Account**, optionally enter:

- AWS profile
- region override
- security severity gate
- full-coverage requirement

Blacklight Desktop uses the same boto3/AWS credential chain as the CLI. Credentials are not stored inside a Blacklight project file.

### Docker

Choose **Docker Project**, select a project directory or type a Dockerfile path, then run the scan.

The existing deterministic Dockerfile scanner runs in the background so the window remains responsive.

### Kubernetes

Choose **Kubernetes Manifests**, select the manifest directory, then run the scan.

No Kubernetes cluster credentials are required for the current static manifest scanner.

## Findings

After a scan, the Findings page shows:

- risk score
- coverage status
- CRITICAL count
- HIGH count
- severity
- resource
- finding title

Selecting a row opens its:

- check ID
- description
- remediation
- deterministic evidence

The desktop does not create a second risk model. It uses the same `ScanRunner`, findings, coverage engine, risk engine, and policy engine as the CLI.

## Reports

The latest desktop scan can be exported as:

```text
JSON
HTML
```

using the same Blacklight report renderers used by command-line scans.

## Distribution

Versioned releases produce direct Windows downloads:

```text
Project-Blacklight-Desktop-Windows-x64.exe
Project-Blacklight-Desktop-Windows-ARM64.exe
```

These executables bundle:

- Python runtime
- Project Blacklight
- PySide6 / Qt
- boto3/botocore
- Docker and Kubernetes scanners

Python does not need to be installed on the destination machine.

The first builds are portable executables rather than MSI installers.

## Code signing

Current alpha desktop executables are not Authenticode-signed.

Windows SmartScreen may therefore show an unknown-publisher warning. Release `SHA256SUMS` can verify artifact integrity, but proper publisher signing is a separate future release task.

## Build locally

Install the desktop build dependencies:

```powershell
python -m pip install -e ".[desktop]"
```

Run the desktop from source:

```powershell
python -m blacklight_security.desktop.app
```

Smoke-test the UI without displaying a window:

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
python -m blacklight_security.desktop.app --smoke-test
```

Build the native executable:

```powershell
python tools/build_desktop.py
```

The result is written under:

```text
desktop-dist/
```

## Architecture

The desktop layer is deliberately thin:

```text
PySide6 Desktop UI
        ↓
DesktopScanRequest
        ↓
shared ScanRunner
        ↓
AWS / Docker / Kubernetes scanners
        ↓
shared Finding model
        ↓
risk + coverage + gates
        ↓
desktop Findings / JSON / HTML
```

This matters for the next phase.

When Blacklight gains live server/SSH scanning, the desktop can add a real Server target form without replacing the findings, reporting, risk, or export layers.

## Current boundary

The first desktop build does not yet:

- scan live servers over SSH
- persist saved target profiles
- store passwords/private keys
- scan live Kubernetes clusters
- manage Docker daemons
- auto-update itself
- install as an MSI
- provide code signing

Those are product-expansion tasks, not hidden capabilities of the current build.
