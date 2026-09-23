# Standalone Executables

Project Blacklight can be packaged as a self-contained command-line executable for Windows, Linux, and macOS.

The standalone build is intended for users who want to run Blacklight without installing Python or using `pip`.

## Release artifacts

Versioned GitHub Releases use stable platform asset names so download/install links do not need to change every release:

```text
Project-Blacklight-Windows-x64.zip
Project-Blacklight-Linux-x64.tar.gz
Project-Blacklight-MacOS-ARM64.tar.gz
```

The exact architecture suffix is derived from the runner that built the executable.

Each archive contains:

```text
project-blacklight-<version>/
├── blacklight        # blacklight.exe on Windows
├── LICENSE
└── README-STANDALONE.txt
```

The GitHub Release also contains a `SHA256SUMS` file covering the Python distributions and every standalone archive.

## One-command installers

The repository includes installers that locate the newest published GitHub Release, download the correct standalone archive for the machine, verify it against the release `SHA256SUMS`, and install the Blacklight executable.

macOS / Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/OloaneShark/Project_Blacklight/main/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/OloaneShark/Project_Blacklight/main/install.ps1 | iex
```

The Unix installer defaults to `~/.local/bin`. The Windows installer defaults to `%LOCALAPPDATA%\ProjectBlacklight\bin` and adds that directory to the user's PATH when necessary.

Set `BLACKLIGHT_INSTALL_DIR` before running the installer to choose another destination.

Because the installer resolves a GitHub Release dynamically, it can install the newest published alpha/prerelease as well as future stable releases.

## No Python runtime required

The executable bundles Blacklight and its Python runtime/dependencies into one executable using PyInstaller.

After extracting the archive:

Windows:

```powershell
.\blacklight.exe --version
.\blacklight.exe scan aws
```

Linux/macOS:

```bash
./blacklight --version
./blacklight scan aws
```

AWS credentials are **not** bundled. Blacklight still uses the normal boto3/AWS credential chain, including AWS profiles, environment variables, and role-based credentials.

## Build locally

Install the standalone build dependency:

```bash
python -m pip install -e ".[standalone]"
```

Build and smoke-test the executable:

```bash
python tools/build_standalone.py
```

The script:

1. clears the prior standalone build directory
2. runs PyInstaller in one-file mode
3. includes Blacklight scanner modules plus boto3/botocore runtime data
4. executes the frozen binary with `--version`
5. checks that the reported version matches `blacklight_security.__version__`
6. bundles the executable with the license and standalone README
7. creates a platform-specific archive under `standalone-dist/`
8. prints the archive SHA-256 digest

## CI validation

`.github/workflows/standalone.yml` builds and smoke-tests standalone archives on:

- `ubuntu-latest`
- `windows-latest`
- `macos-latest`

The workflow runs on relevant pull requests, relevant pushes to `main`, and manual dispatch.

This catches platform-specific freezing/import failures before a tagged release is prepared.

## Versioned release integration

When a version tag is pushed, `.github/workflows/github-release.yml`:

1. validates the release tag/version/changelog/main ancestry
2. builds the Python wheel and source distribution
3. builds standalone executables on Windows, Linux, and macOS with stable release-asset names
4. smoke-tests each standalone binary on the OS that built it
5. downloads all release artifacts into the release-preparation job
6. generates one `SHA256SUMS` file
7. attaches everything to the draft GitHub Release

The PyPI workflow is intentionally restricted to files beginning with:

```text
project_blacklight_security-
```

so Linux/macOS standalone `.tar.gz` archives are never mistaken for Python source distributions.

## Code-signing status

Current early-alpha standalone executables are **not code-signed**.

As a result:

- Windows SmartScreen may display an unknown-publisher warning.
- macOS Gatekeeper may require explicit user approval for a downloaded binary.

The release checksum lets users verify file integrity, but it is not a substitute for platform code signing.

Code signing/notarization can be added later when release identity and signing credentials are established.
