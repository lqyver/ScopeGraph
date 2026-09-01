FROM debian:bookworm-slim AS pd-tools

ARG SUBFINDER_VERSION=2.14.0
ARG DNSX_VERSION=1.2.3
ARG HTTPX_VERSION=1.9.0
ARG NAABU_VERSION=2.6.1
ARG NUCLEI_VERSION=3.8.0
ARG KATANA_VERSION=1.6.1
ARG ALTERX_VERSION=0.1.0
ARG NUCLEI_TEMPLATES_VERSION=10.4.4

RUN apt-get -o Acquire::Retries=4 update \
    && apt-get -o Acquire::Retries=4 install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    mkdir -p /tools /tmp/releases; \
    fetch_tool() { \
      repo="$1"; binary="$2"; version="$3"; \
      archive="${binary}_${version}_linux_amd64.zip"; \
      base="https://github.com/projectdiscovery/${repo}/releases/download/v${version}"; \
      curl --fail --location --retry 4 --retry-all-errors "${base}/${archive}" -o "/tmp/releases/${archive}"; \
      if ! curl --fail --location --retry 1 --retry-all-errors "${base}/${binary}_${version}_checksums.txt" -o "/tmp/releases/${binary}.checksums"; then \
        if ! curl --fail --location --retry 1 --retry-all-errors "${base}/${binary}-checksums.txt" -o "/tmp/releases/${binary}.checksums"; then \
          if ! curl --fail --location --retry 1 --retry-all-errors "${base}/${binary}-${version}-checksums.txt" -o "/tmp/releases/${binary}.checksums"; then \
            curl --fail --location --retry 4 --retry-all-errors "${base}/${binary}-linux-amd64-checksums.txt" -o "/tmp/releases/${binary}.checksums"; \
          fi; \
        fi; \
      fi; \
      grep "  ${archive}$" "/tmp/releases/${binary}.checksums" > "/tmp/releases/${binary}.sha256"; \
      cd /tmp/releases; sha256sum -c "${binary}.sha256"; \
      unzip -j "${archive}" "${binary}" -d /tools; \
      chmod 0755 "/tools/${binary}"; \
    }; \
    fetch_tool subfinder subfinder "$SUBFINDER_VERSION"; \
    fetch_tool dnsx dnsx "$DNSX_VERSION"; \
    fetch_tool httpx httpx "$HTTPX_VERSION"; \
    fetch_tool naabu naabu "$NAABU_VERSION"; \
    fetch_tool nuclei nuclei "$NUCLEI_VERSION"; \
    fetch_tool katana katana "$KATANA_VERSION"; \
    fetch_tool alterx alterx "$ALTERX_VERSION"

RUN set -eux; \
    curl --fail --location --retry 4 --retry-all-errors \
      "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${NUCLEI_TEMPLATES_VERSION}.tar.gz" \
      -o /tmp/releases/nuclei-templates.tar.gz; \
    mkdir -p /nuclei-templates; \
    tar -xzf /tmp/releases/nuclei-templates.tar.gz \
      --strip-components=1 -C /nuclei-templates; \
    test -f /nuclei-templates/.nuclei-ignore

FROM golang:1.25-bookworm AS puredns-builder

ARG PUREDNS_VERSION=2.1.1
RUN GOBIN=/tools go install "github.com/d3mondev/puredns/v2@v${PUREDNS_VERSION}"

FROM debian:bookworm-slim AS massdns-builder

ARG MASSDNS_COMMIT=6bfa47197d78e68b79041d494e280174cb2d6ae1
RUN apt-get -o Acquire::Retries=4 update \
    && apt-get -o Acquire::Retries=4 install -y --no-install-recommends ca-certificates gcc git libc6-dev make \
    && rm -rf /var/lib/apt/lists/* \
    && git clone https://github.com/blechschmidt/massdns.git /src/massdns \
    && cd /src/massdns \
    && git checkout "$MASSDNS_COMMIT" \
    && make \
    && install -Dm0755 bin/massdns /tools/massdns

# Keep the runtime distribution aligned with the two builder stages.  The moving
# `python:3.12-slim` tag recently advanced to Debian trixie, which invalidated
# Docker cache and made Chromium/Nmap installation unexpectedly large and fragile.
FROM python:3.12-slim-bookworm AS runtime

ARG DEBIAN_MIRROR=http://deb.debian.org/debian
ARG DEBIAN_SECURITY_MIRROR=http://security.debian.org/debian-security

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    CHROME_PATH=/usr/bin/chromium \
    NO_COLOR=1

WORKDIR /app

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    set -eux; \
    case "$DEBIAN_MIRROR" in http://*|https://*) ;; *) echo "Invalid DEBIAN_MIRROR" >&2; exit 2;; esac; \
    case "$DEBIAN_SECURITY_MIRROR" in http://*|https://*) ;; *) echo "Invalid DEBIAN_SECURITY_MIRROR" >&2; exit 2;; esac; \
    rm -f /etc/apt/sources.list.d/debian.sources; \
    printf '%s\n' \
      "deb $DEBIAN_MIRROR bookworm main" \
      "deb $DEBIAN_MIRROR bookworm-updates main" \
      "deb $DEBIAN_SECURITY_MIRROR bookworm-security main" \
      > /etc/apt/sources.list; \
    for attempt in 1 2 3 4; do \
      if apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=4 -o Acquire::http::Pipeline-Depth=0 \
          -o APT::Keep-Downloaded-Packages=true update \
        && apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=4 -o Acquire::http::Pipeline-Depth=0 \
          -o APT::Keep-Downloaded-Packages=true install -y --no-install-recommends \
          --fix-missing chromium fonts-noto-cjk nmap; then \
        break; \
      fi; \
      test "$attempt" -lt 4; \
      sleep 3; \
    done; \
    groupadd --gid 10001 scopegraph \
    && useradd --uid 10001 --gid 10001 --home-dir /app --no-create-home \
        --shell /usr/sbin/nologin scopegraph

COPY pyproject.toml README.md alembic.ini ./
COPY constraints ./constraints
COPY apps ./apps
COPY scopegraph ./scopegraph

RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install --constraint constraints/python312.txt .

# Copy after pip installation so ProjectDiscovery's httpx binary wins over the
# Python package's optional command with the same name.
COPY --from=pd-tools /tools/ /usr/local/bin/
COPY --from=puredns-builder /tools/puredns /usr/local/bin/puredns
COPY --from=massdns-builder /tools/massdns /usr/local/bin/massdns
COPY --from=pd-tools /nuclei-templates /app/nuclei-templates

COPY migrations ./migrations
COPY configs ./configs

RUN mkdir -p /data/system /app/.config /app/.cache \
    && chown -R scopegraph:scopegraph /app /data

USER scopegraph

CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
