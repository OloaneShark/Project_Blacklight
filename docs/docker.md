# Docker Distribution

Project Blacklight ships as a container image for CI/CD systems, cloud runners, and users who prefer Docker over a local Python or standalone executable installation.

The release image is published to:

```text
ghcr.io/oloaneshark/project-blacklight
```

Versioned releases use the package version as the image tag:

```text
ghcr.io/oloaneshark/project-blacklight:0.1.0a20
```

Stable non-prerelease releases also update the `latest` tag. Alpha, beta, and release-candidate releases do **not** move `latest`.

## Supported container platforms

Release images are built for:

```text
linux/amd64
linux/arm64
```

Docker/Buildx publishes one multi-platform manifest for the version tag.

## Runtime security defaults

The production image:

- uses a multi-stage build
- installs only the Blacklight runtime and its Python dependencies
- does not contain the repository test suite, legacy Flask app, Git history, or local environment files
- runs as non-root UID/GID `65532:65532`
- sets `PYTHONDONTWRITEBYTECODE=1`
- includes OCI image metadata for version, source, revision, and MIT license
- contains **no AWS credentials**

The default container working directory is:

```text
/workspace
```

The image entry point is the Blacklight CLI itself, so arguments after the image name are passed directly to `blacklight`.

## Run the image

Check the version:

```bash
docker run --rm ghcr.io/oloaneshark/project-blacklight:0.1.0a20 --version
```

Show AWS scan options:

```bash
docker run --rm ghcr.io/oloaneshark/project-blacklight:0.1.0a20 scan aws --help
```

Run one scanner:

```bash
docker run --rm \
  ghcr.io/oloaneshark/project-blacklight:0.1.0a20 \
  scan aws --service s3
```

Blacklight still needs an AWS credential source when a real AWS scan is performed.

### Scan Dockerfiles with the container

Mount a local project read-only and point the Docker scanner at the mounted directory:

```bash
docker run --rm \
  -v "$PWD:/workspace:ro" \
  ghcr.io/oloaneshark/project-blacklight:0.1.0a21 \
  scan docker --path /workspace
```

Dockerfile scanning is static and does not require mounting the host Docker socket.

## AWS credentials

Credentials are deliberately not baked into the image.

For automated environments, prefer short-lived workload credentials such as an assigned IAM role or the credential mechanism native to the CI/cloud platform.

If the host shell already exposes temporary AWS environment credentials, Docker can forward them:

```bash
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_REGION \
  ghcr.io/oloaneshark/project-blacklight:0.1.0a20 \
  scan aws
```

Do not place credentials in the Dockerfile, image layers, repository, or command arguments.

### Local AWS profiles

A local AWS configuration directory can be mounted read-only. On Linux, running the container with the host user's UID/GID avoids common permissions problems with profile files:

```bash
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$HOME/.aws:/aws:ro" \
  -e AWS_SHARED_CREDENTIALS_FILE=/aws/credentials \
  -e AWS_CONFIG_FILE=/aws/config \
  ghcr.io/oloaneshark/project-blacklight:0.1.0a20 \
  scan aws --profile blacklight-audit
```

Docker Desktop permission behavior differs from native Linux, so profile mounts may not require the same `--user` override on macOS or Windows.

## Reports

Console and JSON output can be captured directly by the host shell:

```bash
docker run --rm \
  ghcr.io/oloaneshark/project-blacklight:0.1.0a20 \
  scan aws --format json > blacklight-scan.json
```

HTML reports require Blacklight to write a file. Mount a host directory into the container:

```bash
mkdir -p reports

docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/reports:/reports" \
  ghcr.io/oloaneshark/project-blacklight:0.1.0a20 \
  scan aws --format html --output /reports/blacklight-report.html
```

The same approach works for JSON files created with `--output`.

## CI/CD gates

The container preserves Blacklight's normal exit-code behavior, so it can be used directly as a pipeline gate:

```bash
docker run --rm \
  ghcr.io/oloaneshark/project-blacklight:0.1.0a20 \
  scan aws --fail-on high --require-full-coverage
```

The container process exits with the Blacklight CLI exit code:

```text
0 = requested gates passed
1 = requested security severity threshold failed
2 = operational/credential/coverage failure
```

## Build locally

Resolve the current package version:

```bash
VERSION="$(python -c 'from blacklight_security import __version__; print(__version__)')"
```

Build:

```bash
docker build \
  --build-arg VERSION="$VERSION" \
  --build-arg REVISION="$(git rev-parse HEAD)" \
  -t "project-blacklight:$VERSION" \
  .
```

Smoke-test:

```bash
docker run --rm "project-blacklight:$VERSION" --version
docker run --rm "project-blacklight:$VERSION" scan aws --help
```

PowerShell version resolution:

```powershell
$version = python -c "from blacklight_security import __version__; print(__version__)"
docker build --build-arg VERSION=$version -t "project-blacklight:$version" .
docker run --rm "project-blacklight:$version" --version
```

## Docker CI

`.github/workflows/docker.yml` runs on Docker-related pull requests and relevant pushes to `main`.

It verifies:

1. the image builds
2. `blacklight --version` matches the package version
3. the runtime user is not root
4. the AWS CLI parser starts successfully
5. the OCI image version label matches the package version

## GHCR release publishing

`.github/workflows/docker-release.yml` runs only after a GitHub Release is manually published.

The workflow:

1. checks out the exact release tag
2. verifies the release tag matches `blacklight_security.__version__`
3. authenticates to GitHub Container Registry using the workflow `GITHUB_TOKEN`
4. builds `linux/amd64` and `linux/arm64` images
5. pushes the versioned multi-platform image to GHCR
6. emits build provenance and an SBOM attestation
7. adds `latest` only for non-prerelease releases

The publish job receives only:

```text
contents: read
packages: write
```

No registry password or long-lived container-registry token is stored in the repository.

## First GHCR publication

The first package publication may require checking the container package visibility in GitHub Packages settings. For a public open-source release, confirm that the `project-blacklight` container package is publicly visible after the first successful publish.

## Image integrity

Versioned GitHub Release files use `SHA256SUMS`. Container images use registry content digests and release-build provenance.

For pinned CI usage, a digest is stronger than a mutable tag:

```text
ghcr.io/oloaneshark/project-blacklight@sha256:<digest>
```

The exact digest is available from GHCR after the image is published.
