# syntax=docker/dockerfile:1

ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src

COPY pyproject.toml README.md LICENSE ./
COPY blacklight_security ./blacklight_security

RUN python -m venv /opt/blacklight \
    && /opt/blacklight/bin/python -m pip install --upgrade pip \
    && /opt/blacklight/bin/python -m pip install .

FROM python:${PYTHON_VERSION}-slim AS runtime

ARG VERSION=dev
ARG REVISION=unknown
ARG SOURCE=https://github.com/OloaneShark/Project_Blacklight

LABEL org.opencontainers.image.title="Project Blacklight" \
      org.opencontainers.image.description="Deterministic cloud security scanning and risk visibility toolkit" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.licenses="MIT"

ENV PATH="/opt/blacklight/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/blacklight

COPY --from=builder /opt/blacklight /opt/blacklight
COPY LICENSE /licenses/Project-Blacklight-LICENSE

RUN mkdir -p /home/blacklight /workspace \
    && chown -R 65532:65532 /home/blacklight /workspace

USER 65532:65532
WORKDIR /workspace

ENTRYPOINT ["blacklight"]
CMD ["--help"]
