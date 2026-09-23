# Versioned GitHub Releases

Project Blacklight prepares versioned GitHub Releases from tags after release changes are merged into `main`.

The release tag is the package version prefixed with `v`.

Example:

```text
Package version: 0.1.0a18
Git tag:         v0.1.0a18
```

## Release flow

1. Merge the intended release changes into `main`.
2. Confirm CI is green.
3. Confirm `blacklight_security.__version__` is the intended version.
4. Confirm `CHANGELOG.md` has the matching release entry.
5. Create and push the version tag.
6. GitHub Actions builds and validates the release artifacts.
7. GitHub Actions creates a **draft** GitHub Release with generated notes and attached artifacts.
8. Review the draft release.
9. Manually click **Publish release**.
10. Publishing the release triggers the separate PyPI Trusted Publishing workflow and the GHCR container publishing workflow.

This keeps GitHub Release creation reviewable and prevents an automated tag push from immediately publishing packages or container images.

## Creating the tag

Update local `main` first:

```bash
git switch main
git pull
```

Create the exact version tag:

```bash
git tag v0.1.0a18
git push origin v0.1.0a18
```

The workflow rejects the tag if:

- the tag version does not match `blacklight_security.__version__`
- the tagged commit is not contained in `main`
- the changelog does not contain the matching release heading
- package build validation fails
- the built wheel cannot be installed and executed

## Draft release artifacts

The draft GitHub Release contains the Python distributions plus platform standalone archives:

```text
project_blacklight_security-<version>-py3-none-any.whl
project_blacklight_security-<version>.tar.gz
Project-Blacklight-Windows-<arch>.zip
Project-Blacklight-Linux-<arch>.tar.gz
Project-Blacklight-MacOS-<arch>.tar.gz
SHA256SUMS
```

The checksum file is generated from every artifact attached to the release. Standalone asset names stay stable across releases so the installer scripts can locate the newest platform build without hard-coding a Blacklight version. The standalone archives are built and smoke-tested on the operating system they target.

For alpha, beta, and release-candidate versions, the workflow marks the GitHub Release as a prerelease.

## Rerunning a failed preparation

If the workflow created a draft release before a later step was rerun, it will refresh the draft release assets with `--clobber`.

It will **not** overwrite an already published release.

If the source or package contents need to change after a release has been published:

1. make the fix on a new branch
2. merge it into `main`
3. bump the package version
4. add a new changelog entry
5. create a new version tag

Do not reuse a published version.

## PyPI handoff

The GitHub release preparation workflow and PyPI publishing workflow are deliberately separate.

`.github/workflows/github-release.yml`:

```text
tag push
  -> validate version/main/changelog
  -> build wheel + sdist
  -> build Windows/Linux/macOS standalone archives
  -> twine check
  -> smoke-test wheel and frozen executables
  -> generate SHA256SUMS
  -> create draft GitHub Release
```

`.github/workflows/release.yml`:

```text
human publishes GitHub Release
  -> download the attached wheel + sdist
  -> verify filenames/version
  -> twine check
  -> publish those exact reviewed artifacts to PyPI
```

The PyPI workflow therefore publishes the same distribution files that were reviewed on the GitHub Release instead of rebuilding different artifacts after release approval.


## Container-image handoff

Publishing the reviewed GitHub Release also triggers `.github/workflows/docker-release.yml`.

That workflow builds and publishes:

```text
ghcr.io/oloaneshark/project-blacklight:<version>
```

for both:

```text
linux/amd64
linux/arm64
```

Prerelease versions publish only the explicit version tag. Stable releases also update `latest`.

Container publication is independent from PyPI Trusted Publishing. A PyPI configuration failure does not prevent the separate GHCR workflow from publishing its image, and a GHCR failure does not change the Python release artifacts already attached to the GitHub Release.
