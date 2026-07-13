#!/usr/bin/env bash
# Entrypoint for the app image. Roles: "web" or "worker".
set -euo pipefail

ROLE="${1:-web}"

echo "[entrypoint] waiting for services..."
python /app/scripts/wait_for_services.py || true

case "$ROLE" in
  web)
    echo "[entrypoint] applying migrations..."
    python manage.py migrate --noinput
    echo "[entrypoint] collecting static..."
    python manage.py collectstatic --noinput
    echo "[entrypoint] ensuring admin account..."
    python manage.py create_admin || true
    echo "[entrypoint] starting gunicorn..."
    exec gunicorn config.wsgi:application \
      --bind 0.0.0.0:8000 --workers "${GUNICORN_WORKERS:-3}" --timeout 120 \
      --access-logfile - --error-logfile -
    ;;
  worker)
    echo "[entrypoint] cleaning orphan scanners..."
    python manage.py cleanup_orphan_scanners || true
    echo "[entrypoint] starting celery worker..."
    exec celery -A config worker -l INFO \
      --concurrency "${CELERY_WORKER_CONCURRENCY:-1}"
    ;;
  *)
    echo "unknown role: $ROLE" >&2
    exit 1
    ;;
esac
