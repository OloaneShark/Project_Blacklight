# Versioned GitHub Releases

Project Blacklight has two release paths.

## Alpha / beta / release-candidate versions

Prerelease versions such as `0.1.0a22` are automatically packaged when a new version reaches `main`.

The release workflow:

1. reads `blacklight_security.__version__`
2. verifies the matching changelog heading
3. verifies the source commit is contained in `main`
4. builds the Python wheel and source distribution
5. validates them with `twine check`
6. installs and smoke-tests the wheel
7. builds native CLI standalone archives on Windows, Linux, and macOS for x64 and ARM64
8. builds graphical Blacklight Desktop executables for Windows x64 and ARM64
9. smoke-tests every frozen CLI and desktop executable on its native runner
10. generates `SHA256SUMS`
11. creates the matching `v<version>` tag and a public GitHub prerelease

If a GitHub Release for the version already exists, the automatic release path skips it rather than overwriting published artifacts.

## Stable versions

Stable versions do not auto-publish from a normal `main` push.

Create the exact version tag explicitly:

```bash
git switch main
git pull
git tag v1.0.0
git push origin v1.0.0
```

The same validation/build pipeline runs, but the GitHub Release is created as a draft for human review before publication.

## Release artifacts

A release contains:

```text
project_blacklight_security-<version>-py3-none-any.whl
project_blacklight_security-<version>.tar.gz

Project-Blacklight-Windows-x64.zip
Project-Blacklight-Windows-ARM64.zip
Project-Blacklight-Linux-x64.tar.gz
Project-Blacklight-Linux-ARM64.tar.gz
Project-Blacklight-MacOS-x64.tar.gz
Project-Blacklight-MacOS-ARM64.tar.gz

Project-Blacklight-Desktop-Windows-x64.exe
Project-Blacklight-Desktop-Windows-ARM64.exe

SHA256SUMS
```

Standalone asset names intentionally stay stable across versions so the install scripts can discover the newest compatible archive.

## Public download installers

macOS / Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/OloaneShark/Project_Blacklight/main/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/OloaneShark/Project_Blacklight/main/install.ps1 | iex
```

The installers resolve the newest published GitHub Release, choose the OS/architecture asset, download `SHA256SUMS`, verify the archive, and install the native executable.

## PyPI and GHCR handoff

GitHub prevents ordinary events created with a workflow's own `GITHUB_TOKEN` from recursively starting arbitrary workflows.

For that reason, the PyPI and GHCR workflows support both:

- a normal human `release: published` event
- successful completion of the `Prepare GitHub Release` workflow for automated prereleases

This keeps automated alpha downloads, PyPI publication, and container publication aligned without using a long-lived personal access token.

PyPI still requires the one-time Trusted Publisher setup documented in [publishing.md](publishing.md).

## Published versions are immutable

Do not replace a published version with different source or binaries.

If a published build is wrong:

1. fix the source
2. bump `blacklight_security.__version__`
3. add a changelog entry
4. merge to `main`
5. publish the new version

The release system intentionally refuses to overwrite an existing published release.
