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
10. Publishing the release triggers the separate PyPI Trusted Publishing workflow.

This keeps GitHub Release creation reviewable and prevents an automated tag push from immediately publishing to PyPI.

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

The draft GitHub Release contains:

```text
project_blacklight_security-<version>-py3-none-any.whl
project_blacklight_security-<version>.tar.gz
SHA256SUMS
```

The checksum file is generated from the exact wheel and source archive attached to the release.

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
  -> twine check
  -> smoke-test wheel
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
