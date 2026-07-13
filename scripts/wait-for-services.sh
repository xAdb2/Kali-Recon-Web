#!/usr/bin/env bash
# Thin wrapper around wait_for_services.py (kept for the documented name).
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python "${DIR}/wait_for_services.py"
