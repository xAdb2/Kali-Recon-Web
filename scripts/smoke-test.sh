#!/usr/bin/env bash
# Local-only smoke test. Spins up a DISPOSABLE HTTP target on the default
# bridge and runs a real recon task against it through the running stack.
# NEVER point this at an external host. Requires: the stack already `up`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
DC="docker compose"
TARGET_NAME="kalirecon-smoke-target"

cleanup() { docker rm -f "$TARGET_NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[smoke] ensuring stack is running..."
$DC ps web >/dev/null 2>&1 || { echo "請先執行 docker compose up -d"; exit 1; }

echo "[smoke] starting disposable HTTP target on the default bridge..."
docker rm -f "$TARGET_NAME" >/dev/null 2>&1 || true
docker run -d --name "$TARGET_NAME" python:3.12-slim \
  sh -c 'printf "<html><head><title>Smoke Target</title></head><body>ok</body></html>" > /index.html; cd /; python -m http.server 80' \
  >/dev/null

sleep 2
TARGET_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TARGET_NAME")"
[ -n "$TARGET_IP" ] || { echo "無法取得測試目標 IP"; exit 1; }
echo "[smoke] target IP = ${TARGET_IP}"

echo "[smoke] creating and enqueuing a recon task via the web container..."
TASK_ID="$($DC exec -T web python manage.py shell <<PY
from recon.models import ScanTask
from recon.services.workflow import create_steps
from recon.tasks import run_scan_task
from recon.constants import TaskStatus
from django.utils import timezone
t = ScanTask.objects.create(
    name="smoke", target_ip="${TARGET_IP}",
    target_url="http://smoke.local/", url_scheme="http",
    url_hostname="smoke.local", url_base_path="/",
    requested_tools=["nmap_ports", "http_probe"], authorized=True,
    status=TaskStatus.QUEUED, queued_at=timezone.now(),
)
create_steps(t)
run_scan_task.delay(str(t.id))
print(t.id)
PY
)"
TASK_ID="$(echo "$TASK_ID" | tr -d '\r' | tail -1)"
echo "[smoke] task id = ${TASK_ID}"

echo "[smoke] waiting for completion..."
for _ in $(seq 1 60); do
  STATUS="$($DC exec -T web python manage.py shell -c \
    "from recon.models import ScanTask; print(ScanTask.objects.get(pk='${TASK_ID}').status)" \
    | tr -d '\r' | tail -1)"
  echo "  status=${STATUS}"
  case "$STATUS" in
    COMPLETED|PARTIAL|FAILED|CANCELLED|TIMED_OUT) break ;;
  esac
  sleep 3
done

echo "[smoke] verifying report artifact..."
HASREPORT="$($DC exec -T web python manage.py shell -c \
  "from recon.models import ScanTask; t=ScanTask.objects.get(pk='${TASK_ID}'); print(t.artifacts.filter(name='report.html').exists())" \
  | tr -d '\r' | tail -1)"

if [ "$HASREPORT" = "True" ] && { [ "$STATUS" = "COMPLETED" ] || [ "$STATUS" = "PARTIAL" ]; }; then
  echo "[smoke] PASS — status=${STATUS}, report generated."
  exit 0
fi
echo "[smoke] FAIL — status=${STATUS}, report=${HASREPORT}"
exit 1
