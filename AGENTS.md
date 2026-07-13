# AGENTS.md — KaliRecon Web

Guidance for automated agents and contributors working in this repository.

## What this is
A self-hosted, single-user **authorized reconnaissance** workflow manager.
Django server-rendered UI + Celery workers that launch **ephemeral Docker
scanner containers** per tool step. It is a *control plane for recon tools*,
not an exploitation framework.

## Architecture
```
Windows browser --SSH tunnel--> web (Django/Gunicorn)
                                   |-- PostgreSQL (metadata)
                                   |-- Redis (Celery broker/result)
                                   |-- worker (Celery) --/var/run/docker.sock--> ephemeral scanner containers
                                   `-- shared workspace volume (artifacts, reports)
```
- The Django request process never blocks on a scanner command.
- Each tool step runs in its own throwaway container labelled with task/step
  UUIDs, mounting the workspace volume, with `extra_hosts` = {hostname: IP}.

## Key modules
- `recon/services/target.py` — strict IP/URL validation & normalization.
- `recon/tools/` — plugin per tool (`base.py` has the plugin ABC + expert
  validator). Each plugin pins an allowlisted executable and builds an **argv
  list** (never a shell string).
- `recon/services/workflow.py` — planning (dependency insertion) + sequential
  execution + normalization/dedup + status aggregation.
- `recon/services/docker_runner.py` — ephemeral container lifecycle, cancel by
  label, orphan cleanup.
- `recon/parsers/` — nmap XML, dirsearch JSON/CSV, nuclei JSONL.
- `recon/services/report.py` — HTML + JSON report.

## Hard security rules (do not regress)
- **No shell, ever.** No `shell=True`, `/bin/sh -c`, `bash -c`, `eval`, pipes,
  redirects, command substitution, env assignment, or alternate executables.
- Expert mode: reject shell metacharacters in raw text, then
  `shlex.split(posix=True)`; first token must equal the plugin's executable;
  backend injects output paths and enforces the task IP/host scope.
- The IP↔hostname mapping is mandatory for every HTTP/TLS tool (TCP → IP, SNI &
  Host → hostname). Never scan the hostname via public DNS.
- Scanner containers: non-root, read-only rootfs, `cap_drop ALL`,
  `no-new-privileges`, cpu/mem/pids limits, no `--privileged`. Remove after run.
- Never expose the app publicly: the worker holds `docker.sock` = host-root.
- Validate/normalize all target data; escape all tool-controlled text in
  templates; block path traversal in artifact routes.
- No hardcoded secrets. `DJANGO_SECRET_KEY` and passwords come from env only.

## Scope boundaries (MVP)
Only: the supplied target IP, the hostname of the supplied URL, and ports
selected/discovered on that IP. No subdomains, ASN ranges, reverse-DNS
neighbors, or auto-following out-of-scope redirects.

## Commands
```bash
python -m pytest -q         # tests (uses sqlite via USE_SQLITE=1)
python -m ruff check .      # lint
python manage.py check      # Django system checks
python manage.py makemigrations --check --dry-run
docker compose config -q    # compose validity
./scripts/smoke-test.sh     # local-only smoke (stack must be up)
```
Run with `USE_SQLITE=1 DJANGO_ALLOW_INSECURE_SECRET=1` for local, DB-less runs.

## Definition of done
See `prompt.md` §20 and `IMPLEMENTATION_REPORT.md`. Keep tests, ruff, and
Django checks green; never let expert-command validation silently fall back to
shell execution; keep positive+negative expert tests for every plugin.
