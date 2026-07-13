# Codex Implementation Prompt — KaliRecon Web MVP

## 0. Mission

Build a complete, demo-ready, self-hosted web application named **KaliRecon Web**.

The application is intended for **authorized reconnaissance only**. It runs on a Kali Linux machine, is operated from a Windows browser through an SSH tunnel, and lets the user create one reconnaissance task per authorized target by entering:

- Target IP address
- Target URL, such as `https://test.test.tw/`
- Recon tools to run
- Scan profile and rate limits

Each task must have its own page, execution status, step history, logs, artifacts, normalized findings, and combined HTML report.

The most important target behavior is:

```text
connect_ip = 12.34.56.78
URL/hostname = https://test.test.tw/

Actual TCP connection must reach: 12.34.56.78
TLS SNI must be: test.test.tw
HTTP Host must be: test.test.tw
```

Do not merely scan the hostname using public DNS. The scanner must preserve the user-supplied IP-to-hostname mapping for every HTTP/TLS tool.

This repository must be usable tomorrow with a workflow close to:

```bash
git clone <repository-url>
cd <repository>
./scripts/install.sh
docker compose up -d
```

The web service must bind to `127.0.0.1:8080` by default. The user will access it from Windows through:

```bash
ssh -N -L 8080:127.0.0.1:8080 <kali-user>@<kali-ip>
```

Then open:

```text
http://127.0.0.1:8080
```

---

## 1. Working instructions for Codex

1. Read this entire document before changing files.
2. If the repository is empty, initialize the project from scratch.
3. Create a root-level `AGENTS.md` that summarizes the architecture, coding rules, security boundaries, test commands, and definition of done from this prompt.
4. Do not stop after scaffolding. Implement the working MVP end to end.
5. Do not ask questions unless progress is impossible without a secret or unavailable external account. Make reasonable, documented engineering decisions.
6. Run tests, linters, `docker compose config`, migrations, and a local smoke test before declaring completion.
7. Fix failures rather than only documenting them.
8. Keep commits logical and reviewable.
9. If GitHub authentication is available, push a branch named `codex/kalirecon-mvp` and open a pull request. Do not overwrite unrelated user work.
10. If GitHub authentication is unavailable, leave the repository in a clean state with commits ready to push.
11. At completion, create `IMPLEMENTATION_REPORT.md` containing:
    - What was implemented
    - Architecture decisions
    - Exact startup commands
    - Test results
    - Known limitations
    - Recommended next steps

---

## 2. Scope and safety boundaries

This project is a reconnaissance workflow manager, not an exploitation framework.

### Include in MVP

- Nmap port discovery
- Nmap service detection
- HTTP response probing
- WhatWeb fingerprinting
- Dirsearch content discovery
- TLS certificate inspection
- Safe Nuclei reconnaissance/misconfiguration checks
- Structured parsing
- Reports and artifacts

### Explicitly exclude from automatic MVP workflows

- SQLmap
- Password brute forcing
- Credential stuffing
- Exploit execution
- OS command shells
- File writes to targets
- Destructive HTTP methods
- Denial-of-service templates or tests
- Automatic scanning of unrelated subdomains or neighboring IP addresses
- Arbitrary operating-system shell commands outside the supported reconnaissance tool allowlist
- Shell pipelines, redirections, command chaining, command substitution, environment assignment, or interactive shells entered through the Web UI

The UI must display a clear banner stating that the application is for systems the user owns or is explicitly authorized to assess.

A task creation form must require an authorization acknowledgment checkbox.

---

## 3. Required architecture

Use the following stack unless a dependency is demonstrably incompatible:

- Python 3.12+
- Django with server-rendered templates
- PostgreSQL
- Redis
- Celery
- Gunicorn
- Docker Compose
- Vanilla JavaScript for task polling and UI updates
- Pytest and pytest-django
- Ruff for linting/format checks

Do not add React, Vue, Node build tooling, or a separate frontend repository.

Logical services:

```text
Windows browser
    |
    | SSH tunnel
    v
Django web service
    |
    +-- PostgreSQL: persistent metadata
    +-- Redis: Celery broker/result backend
    +-- Celery worker: workflow orchestration
    +-- Docker runner: ephemeral scanner containers
    +-- Shared workspace volume: raw artifacts and reports
```

The Django request process must never synchronously wait for a scanner command.

### Docker runner design

The Celery worker must start an **ephemeral scanner container for each tool step**, using the Docker API or Docker SDK for Python.

The scanner container must:

- Use a dedicated scanner image based on Kali rolling or another justified Kali-compatible image.
- Receive either a backend-generated command or a validated expert-mode command for the selected allowlisted reconnaissance plugin.
- Never execute `shell=True`, `/bin/sh -c`, `bash -c`, PowerShell, or any equivalent shell wrapper.
- Parse expert-mode command text with `shlex.split()` and execute only the resulting argument array.
- Require the first argument to match the executable allowlisted for the selected plugin.
- Reject shell operators, pipelines, redirects, command substitution, environment assignment, multiline commands, and additional executables.
- Be labeled with task UUID and step UUID.
- Mount the shared workspace volume.
- Receive an `extra_hosts` mapping when the target URL contains a hostname:

```text
test.test.tw -> 12.34.56.78
```

This mapping is how HTTP tools preserve correct DNS resolution, Host header, and TLS SNI.

The worker container may mount `/var/run/docker.sock` only because this is a trusted, local, single-user application. Document clearly that Docker socket access is host-equivalent privilege and the web app must not be exposed publicly.

Do not grant scanner containers `--privileged`.

Use Nmap TCP connect scanning (`-sT`) by default so the scanner container does not require raw-socket capabilities. If an optional advanced mode needs capabilities, keep it disabled and document it, but do not require it for MVP.

---

## 4. Repository structure

Use a clear structure similar to:

```text
.
├── AGENTS.md
├── README.md
├── IMPLEMENTATION_REPORT.md
├── LICENSE
├── .env.example
├── .gitignore
├── Makefile
├── compose.yml
├── compose.prebuilt.yml
├── pyproject.toml
├── manage.py
├── config/
├── recon/
│   ├── models.py
│   ├── forms.py
│   ├── views.py
│   ├── urls.py
│   ├── admin.py
│   ├── tasks.py
│   ├── services/
│   │   ├── target.py
│   │   ├── workflow.py
│   │   ├── docker_runner.py
│   │   ├── report.py
│   │   └── artifacts.py
│   ├── tools/
│   │   ├── base.py
│   │   ├── nmap.py
│   │   ├── http_probe.py
│   │   ├── whatweb.py
│   │   ├── dirsearch.py
│   │   ├── tls.py
│   │   └── nuclei.py
│   ├── parsers/
│   ├── templates/
│   ├── static/
│   └── tests/
├── docker/
│   ├── app.Dockerfile
│   ├── scanner.Dockerfile
│   └── entrypoint.sh
├── scripts/
│   ├── install.sh
│   ├── wait-for-services.sh
│   ├── smoke-test.sh
│   └── create-admin.py
├── fixtures/
│   ├── nmap/
│   ├── dirsearch/
│   └── nuclei/
└── .github/workflows/
    ├── test.yml
    └── images.yml
```

Exact names may differ, but maintain separation of web logic, workflow orchestration, tool plugins, parsers, artifacts, and reports.

---

## 5. Domain model

Implement at least the following concepts. Use UUID primary identifiers for externally visible task-related records.

### ScanTask

Fields should include:

- UUID
- Name
- Target IP
- Original target URL
- Parsed scheme
- Parsed hostname
- Parsed port
- Parsed base path
- Selected profile
- Requested tools
- Per-tool command mode and expert command configuration stored as structured JSON
- Rate limit
- Maximum task duration
- Status
- Authorization acknowledgment
- Created by
- Created, queued, started, finished timestamps
- Cancellation requested timestamp
- Error summary

Supported statuses:

```text
CREATED
QUEUED
RUNNING
CANCELLING
CANCELLED
COMPLETED
PARTIAL
FAILED
TIMED_OUT
```

### ScanStep

Fields:

- UUID
- Parent task
- Tool/plugin name
- Human-readable title
- Order
- Status
- Progress percentage if known
- Command mode: `DEFAULT` or `EXPERT`
- Original expert command text, when used
- Validated argument array stored as JSON
- Sanitized command display
- Scanner container ID, if active
- Exit code
- Start/end timestamps
- Error summary
- stdout artifact
- stderr artifact
- structured-result artifact

Step statuses:

```text
PENDING
QUEUED
RUNNING
COMPLETED
FAILED
SKIPPED
CANCELLED
TIMED_OUT
```

### Service

- Task
- IP
- Port
- Transport protocol
- Service name
- Product
- Version
- Extra info
- Source tool

### Endpoint

- Task
- Canonical URL
- HTTP method, default GET
- Status code
- Title
- Content length
- Content type
- Redirect location
- Source tools, many-to-many or normalized equivalent

### Finding

- Task
- Severity: info, low, medium, high, critical
- Confidence: low, medium, high
- Category
- Title
- Description
- Evidence
- Remediation
- Source tool
- Related service or endpoint when applicable
- Stable deduplication key

Do not label ordinary informational observations as vulnerabilities. For example, server fingerprints and discovered paths are normally informational unless there is evidence of exposure or misconfiguration.

### Artifact

- Task
- Optional step
- Display name
- Artifact type
- Relative path inside the workspace
- MIME type
- Size
- SHA-256
- Created timestamp

All artifact downloads must enforce authentication and ownership/authorization. Prevent path traversal.

---

## 6. Target validation and normalization

Create a dedicated target parser and validator.

### Target IP

- Accept valid IPv4 and IPv6 literals.
- Store normalized form.
- Do not accept shell syntax, CIDR ranges, hostnames, or multiple targets in this field for MVP.

### Target URL

- Optional only if the user selects Nmap-only scanning.
- If present, allow only `http` and `https`.
- Reject URL userinfo such as `user:pass@host`.
- Reject unsupported schemes.
- Normalize hostname using safe IDNA handling.
- Preserve explicit port and base path.
- Strip fragments.
- Reject control characters and malformed percent encoding.

### Scope

MVP scope is exactly:

- The supplied target IP
- The hostname in the supplied target URL
- Ports explicitly selected or discovered on that target IP

Do not automatically expand scope to subdomains, ASN ranges, reverse-DNS neighbors, or redirect destinations on other hosts.

If an HTTP redirect points outside scope, record it but do not follow it automatically.

---

## 7. Tool plugin interface

Implement a reusable plugin abstraction. Each plugin must define approximately:

```python
class ToolPlugin:
    name: str
    title: str
    dependencies: list[str]

    def is_applicable(self, task, context) -> bool: ...
    def build_argv(self, task, step, context) -> list[str]: ...
    def output_files(self, task, step) -> dict[str, str]: ...
    def parse(self, task, step, workspace) -> ParseResult: ...
```

Requirements:

- Fixed allowlisted executable names.
- Fixed backend-controlled flags.
- No arbitrary flags from the browser.
- `subprocess` or Docker command invocation must receive an argument array.
- Every plugin has a timeout.
- Every plugin saves stdout, stderr, exit code, tool version, and structured output.
- A failed optional step must not destroy completed results from earlier steps.

### Dependency behavior

Examples:

- Nmap service detection depends on Nmap port discovery unless the user supplied a fixed allowed port list.
- Dirsearch requires a valid target URL and a successful HTTP baseline.
- WhatWeb requires a target URL.
- TLS inspection applies only to HTTPS.
- Nuclei Web checks require a reachable HTTP target.

If a user selects a dependent tool, automatically insert required prerequisite steps and clearly show them in the UI.

---

## 8. Required tool behavior

### 8.1 Nmap port discovery

Default safe profile:

```text
-sT -Pn --open --top-ports 1000
```

Standard profile may scan all TCP ports with conservative timing and a task timeout.

Write XML output and parse it. Do not parse human-formatted terminal output as the primary data source.

### 8.2 Nmap service detection

Run only against discovered open TCP ports.

Use conservative version detection and default scripts suitable for service identification. Do not include intrusive NSE categories.

Write and parse XML output.

### 8.3 HTTP probe

Implement a reliable baseline probe using curl and/or an available HTTP probing tool.

Capture:

- Status code
- Headers
- Title when practical
- Content type
- Content length
- Redirect location
- Final in-scope URL
- TLS verification result

The target hostname must resolve to the user-supplied target IP inside the scanner container.

Do not silently follow redirects outside scope.

### 8.4 WhatWeb

Run at a conservative aggression level suitable for fingerprinting. Store machine-readable output when available and preserve raw output.

### 8.5 Dirsearch

Use backend-defined wordlists bundled or installed in the scanner image.

Profiles:

- Safe: small/common list, low thread count, low request rate
- Standard: medium list and moderate concurrency
- Deep may be represented in the UI but can remain disabled with a clear “not implemented in MVP” message; do not fake support

Capture at least:

- URL/path
- Status code
- Content length
- Redirect

Use JSON or CSV output if supported by the installed version. Include a parser fixture and tests.

### 8.6 TLS inspection

For HTTPS targets, capture:

- Certificate subject
- Issuer
- Validity dates
- Subject alternative names
- Verification result for the supplied hostname
- Negotiated protocol/cipher if easily available

Use the supplied hostname as SNI while connecting to the supplied IP through the task container mapping.

### 8.7 Nuclei

Nuclei is optional and must be conservative.

Only run allowlisted reconnaissance-oriented templates/tags such as:

- technology detection
- exposure
- misconfiguration

Exclude:

- DoS
- fuzzing-heavy templates
- headless templates unless explicitly justified
- brute-force templates
- intrusive exploitation templates

Set a backend-controlled rate limit and timeout.

Use JSONL output and parse it.

If the exact Kali package is unavailable or the installed command name differs, handle it at image build time and document the result. The scanner image build must verify required executables with `command -v` and fail clearly for mandatory tools.

### 8.8 Expert custom command mode

Because this is a trusted, local, authenticated, single-user application, implement an optional **expert custom command mode** for each supported tool.

The task creation page must let the user switch each selected tool between:

- **Default mode**: backend-generated command based on the selected profile and structured options.
- **Expert mode**: an editable command field pre-populated with the exact default command so the user can modify tool-specific flags before starting the task.

Supported expert-mode executables are limited to the existing tool plugins:

```text
nmap
curl or the configured HTTP probe executable
whatweb
dirsearch
openssl
nuclei
```

This feature is a command-line editor for allowlisted reconnaissance tools, **not a general remote shell**.

#### Required validation and execution rules

1. Only authenticated superusers may use expert mode.
2. Expert mode must be controlled by `ENABLE_EXPERT_COMMANDS`, documented in `.env.example`. Enable it by default only for the localhost/SSH-tunnel deployment profile; production-style deployments must be able to disable it.
3. Accept exactly one command for one selected tool step. Reject multiline commands.
4. Parse the text with `shlex.split(posix=True)` and execute the resulting argument array directly.
5. Never use `shell=True`, `/bin/sh -c`, `bash -c`, `eval`, `exec`, command substitution, or a shell wrapper.
6. The first token must exactly match the executable assigned to that tool plugin. Do not allow an arbitrary executable path, alternate executable, interpreter, or wrapper such as `python`, `env`, `sudo`, `xargs`, `sh`, or `bash`.
7. Reject shell/control syntax including at least:

```text
;
&&
||
|
>
>>
<
<<
&
`
$(...)
${...}
newlines
carriage returns
```

8. Reject environment-variable assignments before the executable or as standalone command tokens.
9. The backend must enforce the task target and scope even in expert mode:
   - Nmap may scan only the task target IP.
   - HTTP tools may request only the task URL/hostname and discovered in-scope ports.
   - The task-specific IP-to-hostname mapping remains mandatory.
   - Extra target IPs, hostnames, URLs, CIDR ranges, input lists, stdin target lists, and neighboring hosts must be rejected.
10. The backend owns artifact output paths. It must inject or normalize required machine-readable output arguments so results are always written beneath the step workspace. Reject output paths outside the step workspace and path traversal.
11. Tool-specific validators must reject options that escape the intended reconnaissance boundary. At minimum reject:
   - Nmap arbitrary script paths, `--script` values outside a small backend allowlist, input lists, decoys, spoofing, packet data files, interactive mode, and output paths outside the workspace.
   - Dirsearch arbitrary target lists, arbitrary output paths, raw request files outside an approved upload/workspace area, and wordlist paths outside the scanner image wordlist allowlist or task workspace.
   - Nuclei arbitrary template/code paths, code templates, headless templates, fuzzing-heavy, brute-force, DoS, workflow files, target lists, and output paths outside the workspace.
   - Curl file uploads, arbitrary request-body file reads, proxy configuration, Unix sockets, local file URLs, credential files, config-file loading, and output paths outside the workspace unless specifically implemented and validated.
   - OpenSSL commands other than the TLS/certificate inspection subcommands implemented by the plugin.
12. Validate numeric resource options against administrator-defined maxima, including threads, concurrency, request rate, retries, timeout, and maximum execution duration.
13. Before submission, show:
   - Editable expert command
   - Validated/normalized command preview
   - Warnings describing any backend-added or replaced target/output arguments
14. Save the original text, validated argv, final executed argv, tool version, user, timestamps, and validation decision in the audit trail.
15. Re-run must copy expert commands but require validation again against the current policy.
16. A validation failure must prevent task creation or mark only that step invalid; it must never silently fall back to shell execution.
17. Include unit tests for accepted and rejected command examples for every supported plugin.

#### UI behavior

For each selected tool, provide a collapsible card containing:

```text
[ ] 使用進階自訂指令

預設／自訂指令：
[ nmap -sT -Pn ... ]

驗證後實際命令（唯讀）：
[ nmap -sT -Pn ... -oX /workspace/... TARGET_IP ]
```

When expert mode is disabled, show the generated command as read-only. Display a prominent warning in Traditional Chinese that expert commands are powerful, are restricted to the selected tool, and still must remain within the authorized target scope.

---

## 9. Workflow execution

A task should execute approximately:

```text
1. Validate and normalize target
2. Create workspace
3. Record tool versions
4. Nmap port discovery, if selected
5. Nmap service detection, if selected
6. HTTP baseline, if URL present and Web tools selected
7. WhatWeb, if selected and applicable
8. TLS inspection, if selected and applicable
9. Dirsearch, if selected and applicable
10. Nuclei, if selected and applicable
11. Parse and deduplicate records
12. Generate HTML and JSON report
13. Finalize task status
```

Run steps sequentially inside one task for MVP. Allow multiple tasks with a default Celery worker concurrency of 1 or 2, configurable by environment variable.

### Partial completion

If some steps succeed and another optional step fails or times out:

- Preserve all successful results.
- Generate the report.
- Mark the task `PARTIAL`.
- Clearly identify failed/skipped steps.

### Cancellation

When cancellation is requested:

1. Mark task `CANCELLING`.
2. Find active scanner containers by labels.
3. Stop/kill them safely.
4. Mark remaining pending steps cancelled.
5. Preserve completed artifacts.
6. Generate a partial report if possible.
7. Mark task `CANCELLED`.

A database status change alone is not sufficient; active scanner processes must actually stop.

### Timeouts

Implement:

- Per-step timeout
- Whole-task timeout
- Scanner container cleanup in `finally` paths
- Recovery for orphaned containers after worker restart

Add a management command such as:

```bash
python manage.py cleanup_orphan_scanners
```

---

## 10. Workspace and artifacts

Use a persistent Docker named volume with a fixed configurable name, for example:

```text
kalirecon_workspaces
```

Per-task layout:

```text
/workspace/<task-uuid>/
├── metadata.json
├── steps/
│   ├── 01-nmap-ports/
│   ├── 02-nmap-services/
│   ├── 03-http-probe/
│   ├── 04-whatweb/
│   ├── 05-tls/
│   ├── 06-dirsearch/
│   └── 07-nuclei/
├── normalized/
│   ├── services.json
│   ├── endpoints.json
│   └── findings.json
└── reports/
    ├── report.html
    └── report.json
```

Each step directory should contain as applicable:

```text
command.json
version.txt
stdout.log
stderr.log
result.xml / result.json / result.jsonl / result.csv
step.json
```

Store a sanitized display command. Do not expose secrets in logs.

Compute SHA-256 and size for registered artifacts.

---

## 11. Web UI requirements

All user-facing UI text must be in **Traditional Chinese (zh-TW)**.

Use a clean, functional, dark-friendly interface without external CDN dependencies at runtime.

### Authentication

- Django authentication is required for every page except login and health check.
- Include login/logout.
- Provide an installation flow that creates the initial admin account from prompted or generated values.
- Never commit default production credentials.

### Dashboard

Show:

- Create task button
- Recent task list
- Task name
- Target IP
- Target URL
- Selected tools
- Status badge
- Progress
- Created/start/end time
- Link to task page

Allow filtering by status and searching by task name, IP, or hostname.

### Create task page

Fields:

- Task name
- Target IP
- Target URL
- Profile: Safe or Standard
- Tool checkboxes
- Request rate limit
- Maximum task duration
- Authorization acknowledgment checkbox
- Per-tool command mode: Default or Expert, visible only to superusers when `ENABLE_EXPERT_COMMANDS=true`
- Per-tool editable expert command field pre-populated from the generated default command
- Read-only normalized command preview and validation messages

Display tool dependencies before submission.

Do not expose a general-purpose shell or unrestricted executable/argument input. Expert commands must follow Section 8.8 and remain limited to the selected allowlisted tool and authorized target.

### Task detail page

Provide tabs or sections:

1. Overview
2. Steps
3. Services
4. Web endpoints
5. Findings
6. Live/recent logs
7. Artifacts
8. Report

Overview must show:

- Task status
- Progress
- Target IP
- Scheme/hostname/port/base path
- Selected profile and tools
- Whether each step used Default or Expert command mode
- Sanitized final executed command and validation warnings
- Current step
- Start/end time
- Error/partial completion summary

Step list must show:

- Order
- Tool
- Status
- Start/end
- Duration
- Exit code
- Artifact links
- Error summary

### Progress updates

Use reliable polling with a JSON status endpoint every 2–3 seconds. SSE is optional, not required for MVP.

Do not require a full page refresh to observe task progress.

### Actions

- Start queued task automatically after creation
- Cancel running task
- Re-run task using copied settings
- Download HTML report
- Download JSON report
- Download individual artifacts

Deletion can be omitted in MVP or restricted to superusers with confirmation.

---

## 12. Report requirements

Generate a self-contained HTML report using a Django/Jinja-style template and local CSS.

Report sections:

1. Executive summary
2. Target definition and enforced IP/hostname mapping
3. Scan configuration
4. Completion status and failed/skipped steps
5. Open ports and services
6. HTTP/TLS summary
7. Discovered endpoints
8. Findings grouped by severity
9. Items requiring manual verification
10. Tool versions and execution metadata
11. Artifact index
12. Scope and authorization disclaimer

Also generate a normalized JSON report.

Report rules:

- Escape all tool-controlled text.
- Do not insert raw HTML from target responses.
- Deduplicate endpoints and findings.
- Preserve source-tool attribution.
- Clearly distinguish observation, possible issue, and confirmed finding.
- A scanner error must not be presented as a target vulnerability.

---

## 13. Security requirements

This web app can indirectly start security tools and therefore must be treated as a privileged control plane.

Required controls:

- Bind web port to `127.0.0.1` by default.
- Require authentication.
- CSRF protection enabled.
- `DEBUG=False` by default outside tests.
- Secure secret key through environment variables.
- Strict host configuration.
- No `shell=True`.
- No user-controlled executable path.
- Expert-mode flags are allowed only after plugin-specific validation under Section 8.8.
- No general-purpose shell, shell operators, command chaining, pipelines, redirects, command substitution, or alternate executables.
- Validate and normalize all target data.
- Escape output in templates.
- Prevent path traversal in artifact routes.
- Use database transactions for critical task transitions.
- Audit creation, cancellation, rerun, and administrative actions.
- Rate-limit task creation at the application level if practical.
- Limit active task count.
- Set scanner CPU/memory/PID limits.
- Run scanner image as a non-root user where possible.
- Read-only scanner root filesystem where practical, with writable mounted workspace and temporary directory only.
- Remove scanner containers after completion.
- Label and clean orphaned containers.
- Do not expose Redis or PostgreSQL ports to the host.
- Add security headers appropriate for a local Django application.

Document the Docker socket trust risk prominently in README.

---

## 14. Docker and deployment requirements

### Compose services

At minimum:

- `web`
- `worker`
- `redis`
- `db`

Optional:

- `scanner-build` target/image, but scanner should not be a long-running service

Requirements:

- Health checks for PostgreSQL, Redis, and web.
- Dependency startup waits.
- Named database and workspace volumes.
- Web binds to `127.0.0.1:${WEB_PORT:-8080}`.
- Redis and PostgreSQL are internal only.
- Restart policies suitable for a local service.
- Log rotation options.

### Install script

Create an idempotent `scripts/install.sh` that:

1. Verifies Kali/Debian-like environment.
2. Verifies Git, Docker Engine, and Docker Compose plugin.
3. Provides actionable installation guidance if missing; do not silently install Docker through unsafe one-line remote scripts.
4. Copies `.env.example` to `.env` when needed.
5. Generates a strong Django secret.
6. Prompts for admin username/email/password or generates a one-time random password.
7. Derives GHCR image names from the Git remote when possible.
8. Offers:
   - Prebuilt image mode
   - Local build fallback
9. Starts dependencies.
10. Runs migrations.
11. Collects static files.
12. Creates/updates the initial admin safely.
13. Prints exact SSH tunnel and browser instructions.

Do not print secrets again after initial setup unless explicitly requested.

### Makefile

Include useful commands:

```text
make install
make build
make pull
make up
make down
make restart
make logs
make migrate
make createsuperuser
make test
make lint
make smoke
make clean-orphans
```

---

## 15. Prebuilt images and GitHub Actions

Create GitHub Actions workflows.

### Test workflow

On pull requests and pushes:

- Install Python dependencies
- Run Ruff
- Run Pytest
- Run Django checks
- Run migration consistency check
- Run `docker compose config`
- Build app and scanner images, at least on main or when Docker files change

Tests must not scan public hosts.

### Image workflow

On push to `main` and version tags:

- Build app image
- Build scanner image
- Push to GHCR
- Use GitHub repository owner/name-derived tags
- Publish `latest`, commit SHA, and semantic tag when applicable
- Use `permissions: packages: write, contents: read`
- Add build cache
- Generate image metadata

Create `compose.prebuilt.yml` that overrides local builds with GHCR image variables.

The README must explain that GHCR package visibility may need to be set appropriately before unauthenticated pulls.

Local build must remain a supported fallback.

---

## 16. Scanner image

Build a reproducible scanner image and pin or record versions where practical.

Required commands in the image:

- `nmap`
- `curl`
- `openssl`
- `whatweb`
- `dirsearch`
- `nuclei`, when reliably available
- basic utilities such as `jq`, `ca-certificates`, and Python as needed

Optional:

- ProjectDiscovery HTTP probing utility if reliably installable
- `testssl.sh` if it does not make the image fragile

At build time:

- Verify mandatory executables with `command -v`.
- Print tool versions.
- Fail clearly if mandatory tools are missing.
- If Nuclei templates are required, define how they are installed/updated and record the template version. Do not update templates on every task run.

Keep the MVP stable over adding many tools.

---

## 17. Tests

Implement meaningful tests, not placeholders.

Required unit/integration coverage:

### Validation

- Valid IPv4
- Valid IPv6
- Invalid IP/CIDR/multiple targets
- Valid HTTP/HTTPS URLs
- Rejection of unsupported scheme
- Rejection of URL userinfo
- Hostname normalization
- Explicit port and path parsing

### Command safety

- Malicious-looking target strings cannot introduce extra arguments
- Every plugin returns an argv list
- No plugin uses a shell
- Fixed executable allowlist

### Parsers

Use committed fixture files for:

- Nmap XML
- Dirsearch JSON or CSV
- Nuclei JSONL

Test normal results and malformed/truncated results.

### Workflow

- Dependency insertion
- Successful task
- Partial task
- Failed task
- Cancellation state transitions
- Timeout state transitions

### Report

- HTML escapes target/tool-controlled strings
- JSON report validates expected schema
- Deduplication works

### Artifact access

- Unauthenticated request denied
- Authenticated valid artifact succeeds
- Path traversal denied

### Runner

Mock Docker for most tests.

Include one optional local smoke test that runs against a disposable local HTTP test service only. Never point CI at an external target.

---

## 18. Observability and health

Implement:

- `/healthz` for basic web health
- A richer authenticated status page showing DB, Redis, Celery, Docker socket, scanner image, and mandatory tool availability
- Structured application logs
- Task and step audit events
- Clear user-visible error messages

Do not leak full exception traces to normal users when DEBUG is disabled.

---

## 19. README requirements

Write a complete Traditional Chinese README with:

1. Project purpose
2. Authorization-only warning
3. Architecture diagram in Mermaid or text
4. Prerequisites
5. Fast installation
6. Local build installation
7. Prebuilt GHCR installation
8. SSH tunnel instructions from Windows PowerShell and Windows Terminal
9. First login
10. Creating a task
11. Explanation of IP/hostname/SNI mapping
12. Supported tools, profiles, and expert custom command mode
13. Report and artifact locations
14. Cancel/retry behavior
15. Updating the application
16. Backup and restore
17. Troubleshooting
18. Docker socket security warning
19. Known limitations
20. Development and test commands

Include exact copy-paste commands.

Provide a concise “tomorrow at the venue” checklist:

```text
1. Start Kali
2. Verify Docker
3. Clone repository
4. Run install script
5. Start compose stack
6. Create SSH tunnel from Windows
7. Open browser
8. Create authorized recon task
```

---

## 20. Definition of done

Do not claim completion until all of the following are true:

- `docker compose config` succeeds.
- App and scanner images build successfully.
- Django migrations apply to a clean database.
- Admin account creation works.
- Login works.
- A task can be created from the UI.
- Celery receives the task.
- A mocked or local-only scan completes.
- Task progress updates without page refresh.
- Task detail page displays steps.
- Nmap fixture parsing creates Service records.
- Dirsearch fixture parsing creates Endpoint records.
- Nuclei fixture parsing creates Finding records.
- HTML and JSON reports are generated.
- Artifacts can be downloaded only by authenticated users.
- Cancellation stops a labeled test scanner container.
- Failed optional step results in `PARTIAL`, not total data loss.
- Tests pass.
- Ruff passes.
- Django system checks pass.
- README startup instructions have been manually verified.
- No hardcoded passwords, tokens, or secret keys exist in tracked files.
- Expert mode can be enabled or disabled through environment configuration.
- A superuser can edit the command for every supported tool and see the normalized final argv before execution.
- Expert commands execute without a shell and cannot invoke a different executable, a second target, a pipeline, a redirect, or a command chain.
- Plugin-specific expert-command validation has positive and negative unit tests.

---

## 21. Non-MVP roadmap — document but do not implement unless all MVP criteria pass

Document these as future work:

- Additional scanner nodes over SSH
- Role-based permissions
- Per-user task ownership
- WebSocket/SSE live logs
- Virtual-host enumeration
- JavaScript endpoint extraction
- Custom wordlist management
- Scheduled scans
- Diffing two scans of the same target
- PDF export
- Plugin marketplace
- Rootless Podman runner
- SQLmap as a separate manually approved child task based on a selected captured HTTP request

Do not spend MVP implementation time on these before the definition of done is satisfied.

---

## 22. Final response expected from Codex

When implementation is finished, report:

1. Branch and commit hashes
2. Pull request URL, if created
3. Test/lint/build commands executed and their results
4. Exact fresh-install commands
5. Exact Windows SSH tunnel command
6. Initial login creation method
7. Any requirement not completed, with an honest reason
8. Security limitations that remain

