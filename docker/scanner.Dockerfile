# KaliRecon Web — scanner image. Ephemeral, non-root, read-only rootfs at run.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Mandatory reconnaissance tools plus small utilities.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        curl \
        openssl \
        whatweb \
        dirsearch \
        nuclei \
        jq \
        ca-certificates \
        python3 \
    && rm -rf /var/lib/apt/lists/*

# Optional: subfinder for passive subdomain enumeration. Non-fatal if the
# package is unavailable — the subdomains step then fails gracefully at runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends subfinder \
    && rm -rf /var/lib/apt/lists/* \
    || echo "WARN: subfinder unavailable in this base image"

# Bundled wordlists (backend-defined allowlist directory).
COPY docker/wordlists/ /opt/wordlists/

# Nuclei templates: fetched once at build time and recorded. If the build host
# is offline this is non-fatal; the nuclei step will then fail gracefully.
ENV NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates
RUN mkdir -p /opt/nuclei-templates \
    && HOME=/tmp nuclei -update-templates \
         -update-template-dir /opt/nuclei-templates -disable-update-check \
       || echo "WARN: nuclei template update skipped (offline build)"; \
    HOME=/tmp nuclei -version 2>/dev/null | tee /opt/nuclei-templates/VERSION.txt || true
RUN chmod -R a+rX /opt/nuclei-templates /opt/wordlists

# Verify mandatory executables exist; fail the build clearly if not.
RUN set -e; for tool in nmap curl openssl whatweb dirsearch nuclei jq; do \
      if ! command -v "$tool" >/dev/null 2>&1; then \
        echo "FATAL: required tool '$tool' missing from scanner image" >&2; exit 1; \
      fi; \
    done

# Print recorded versions at build time.
RUN echo "=== scanner tool versions ===" \
    && nmap --version | head -1 \
    && curl --version | head -1 \
    && openssl version \
    && (whatweb --version 2>/dev/null | head -1 || true) \
    && (dirsearch --version 2>/dev/null | head -1 || true) \
    && (nuclei -version 2>/dev/null | head -1 || true) \
    && (subfinder -version 2>/dev/null | head -1 || echo "subfinder: not installed") \
    && jq --version

# Non-root scanner user. Workspace + /tmp are the only writable mounts at run.
RUN useradd --create-home --uid 10001 scanner \
    && mkdir -p /workspace && chown scanner:scanner /workspace
USER scanner
WORKDIR /workspace
ENV HOME=/tmp

# Default command is a no-op; the runner always supplies an explicit argv.
CMD ["nmap", "--version"]
