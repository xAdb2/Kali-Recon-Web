# IMPLEMENTATION_REPORT.md — KaliRecon Web MVP

## 1. What was implemented
A complete, demo-ready Django + Celery + Docker reconnaissance workflow manager
matching `prompt.md`.

- **Domain model** (`recon/models.py`): `ScanTask`, `ScanStep`, `Service`,
  `Endpoint`, `Finding`, `Artifact`, `AuditEvent` with UUID PKs and the full
  status enums (§5). Migrations generated and applied to a clean DB.
- **Target validation** (`recon/services/target.py`): strict IPv4/IPv6 literal
  parsing (rejects CIDR/hostnames/multiple targets/shell), http(s)-only URL
  parsing with IDNA normalization, userinfo/scheme/control-char rejection,
  explicit port + base path, fragment stripping.
- **Tool plugins** (`recon/tools/`): base ABC + expert validator, and plugins
  for nmap (ports/services), curl HTTP probe, WhatWeb, TLS (openssl), Dirsearch,
  Nuclei. Every plugin pins an allowlisted executable and returns an **argv
  list**. Expert mode: raw shell-metacharacter rejection → `shlex.split(posix=True)`
  → executable pinning → per-tool scope/output enforcement (§8.8).
- **Parsers** (`recon/parsers/`): Nmap XML, Dirsearch JSON/CSV, Nuclei JSONL,
  each tolerant of malformed/truncated input; committed fixtures.
- **Docker runner** (`recon/services/docker_runner.py`): ephemeral per-step
  containers labelled with task/step UUIDs, `extra_hosts` mapping, workspace
  volume mount, non-root user, read-only rootfs + tmpfs, `cap_drop ALL`,
  `no-new-privileges`, cpu/mem/pids limits, removal on completion, label-based
  cancellation and orphan cleanup.
- **Workflow** (`recon/services/workflow.py`): dependency insertion, sequential
  execution, per-step + whole-task timeout handling, cancellation, partial
  completion, normalization + dedup, status aggregation.
- **Reports** (`recon/services/report.py` + template): self-contained HTML
  (all tool text auto-escaped) and normalized JSON, all 12 sections (§12).
- **Web UI** (zh-TW, dark, no runtime CDN): login, dashboard w/ filter+search,
  create task with per-tool expert cards + live normalized-command preview,
  task detail with tabs and 3s JSON polling, artifacts/report download,
  `/healthz` and an authenticated `/status/` health page.
- **Celery** task + `cleanup_orphan_scanners` and `create_admin` management
  commands.
- **Infra**: `docker/app.Dockerfile`, `docker/scanner.Dockerfile` (Kali,
  build-time `command -v` verification + version print), `entrypoint.sh`,
  `compose.yml` (web/worker/redis/db, healthchecks, internal-only DB/Redis,
  web bound to `127.0.0.1:${WEB_PORT}`, named volumes, log rotation),
  `compose.prebuilt.yml`, `Makefile`, `scripts/` (install/smoke/wait/create-admin),
  GitHub Actions (`test.yml`, `images.yml`), `.env.example`, docs.

## 2. Architecture decisions
- **No shell, argv-only** everywhere; expert mode is a validated command-line
  editor, not a shell. Raw metacharacter rejection happens *before* tokenizing.
- **IP↔host mapping** enforced via container `extra_hosts` so TCP reaches the
  user IP while SNI/Host use the hostname — never public-DNS-only.
- **SQLite for tests, PostgreSQL for runtime**: settings auto-select SQLite when
  running tests without `POSTGRES_HOST` (or `USE_SQLITE=1`), keeping CI DB-less.
- **Workspace named volume** with a fixed name (`kalirecon_workspaces`) shared by
  web/worker and mounted read-write into each scanner, so the runner and Compose
  agree on the volume identity.
- **Worker holds `docker.sock`** (documented host-equivalent privilege); the app
  must never be exposed publicly.

## 3. Exact startup commands
```bash
git clone <repo-url> && cd Kali-Recon-Web
./scripts/install.sh          # prepares .env, secret, admin, builds/pulls, starts
docker compose up -d          # (install.sh already does this)
```
Windows SSH tunnel:
```powershell
ssh -N -L 8080:127.0.0.1:8080 <kali-user>@<kali-ip>
```
Then open `http://127.0.0.1:8080`.

Initial admin: `.env` `ADMIN_USERNAME` (default `admin`); if `ADMIN_PASSWORD`
is empty a one-time password is printed to the web container log
(`docker compose logs web | grep 一次性`).

## 4. Test results (executed on the dev host)
Run with `USE_SQLITE=1 DJANGO_ALLOW_INSECURE_SECRET=1`:

| Check | Command | Result |
|-------|---------|--------|
| Unit/integration tests | `pytest` | **118 passed** |
| Lint | `ruff check .` | **All checks passed** |
| Django checks | `manage.py check` | **0 issues** |
| Migration consistency | `makemigrations --check --dry-run` | **No changes detected** |
| Compose validity | `docker compose config -q` | **OK** (base + prebuilt overlay) |
| Static | `collectstatic` (manifest, DEBUG off) | **130 files, 390 post-processed** |
| Page render smoke | test client GET `/`, `/tasks/new/`, `/status/`, detail, status JSON, report | **all 200 / rendered** |

Coverage includes: target validation (valid/invalid IPv4/IPv6/CIDR/userinfo/
scheme/IDNA/port/path), expert-command positive+negative cases for **every**
plugin, no-shell/allowlist assertions, parser normal+malformed fixtures,
dependency insertion, successful/partial/failed/cancelled/timed-out workflow
transitions, report HTML escaping + JSON schema + dedup, artifact auth + path
traversal, and label-based container cancellation/orphan cleanup (mocked Docker).

## 5. Known limitations / not executed on this host
- **Docker image builds, `docker compose up`, and the live `smoke-test.sh` were
  not run on the development host** because the Docker daemon was not running
  and only Python 3.10 was available locally (images target 3.12). All
  Docker-*independent* verification above passed. The runner and cancellation
  logic are covered by mocked-Docker unit tests, and `docker compose config`
  validates both compose files. These must be run once on the Kali host:
  `docker compose build && docker compose --profile scanner build scanner-build
  && docker compose up -d && ./scripts/smoke-test.sh`.
- **Nuclei templates** are fetched at image build time (requires network); an
  offline build leaves the Nuclei step to fail gracefully (task → PARTIAL).
- **psycopg** is not installed in the local dev venv (SQLite used for tests); it
  is pinned in `requirements.txt` and installed in the app image.
- TLS certificate decoding uses the stdlib `ssl._ssl._test_decode_cert` helper;
  if unavailable it degrades to text-only parsing of the openssl output.
- Deep Dirsearch profile is intentionally **not implemented** (surfaced as such).

## 6. Recommended next steps
- Run the full Docker build + `smoke-test.sh` on the Kali host to tick the
  remaining Docker-dependent DoD items end to end.
- Pin exact tool versions in the scanner image and record the Nuclei template
  version file into artifacts.
- Add per-user task ownership + RBAC and WebSocket/SSE live logs (roadmap §21).

## 7. Security limitations that remain
- The worker's Docker socket access is host-root-equivalent; the app is a
  privileged control plane and must stay on localhost/SSH-tunnel only.
- Scanner egress uses the default bridge so tools can reach the target; network
  segmentation of scanner containers is left to the operator.
