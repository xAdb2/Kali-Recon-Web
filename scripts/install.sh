#!/usr/bin/env bash
# KaliRecon Web installer — idempotent bootstrap for a Kali/Debian-like host.
# Prepares .env, generates a secret, derives image names, builds or pulls
# images, and starts the stack. Does not install Docker for you.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log()  { printf '\033[36m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

# --- 1. environment sanity -------------------------------------------------
if [ -r /etc/os-release ]; then
  . /etc/os-release
  case "${ID:-}${ID_LIKE:-}" in
    *debian*|*kali*|*ubuntu*) : ;;
    *) warn "未偵測到 Kali/Debian 類系統（ID=${ID:-?}）。將繼續，但未經測試。" ;;
  esac
else
  warn "找不到 /etc/os-release，略過系統檢查。"
fi

command -v git >/dev/null 2>&1 || die "缺少 git。請先安裝：sudo apt install git"
command -v docker >/dev/null 2>&1 || die "缺少 Docker Engine。安裝指引：https://docs.docker.com/engine/install/debian/"
if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
else
  die "缺少 Docker Compose plugin。請安裝 docker-compose-plugin。"
fi
docker info >/dev/null 2>&1 || die "無法連線 Docker daemon（是否需要 sudo 或加入 docker 群組？）。"

# --- 2. .env ---------------------------------------------------------------
if [ ! -f .env ]; then
  cp .env.example .env
  log "已從 .env.example 建立 .env"
fi

set_env() { # key value
  local key="$1" val="$2"
  if grep -qE "^${key}=" .env; then
    # portable in-place edit
    tmp="$(mktemp)"; sed "s|^${key}=.*|${key}=${val}|" .env > "$tmp" && mv "$tmp" .env
  else
    printf '%s=%s\n' "$key" "$val" >> .env
  fi
}
get_env() { grep -E "^$1=" .env | head -1 | cut -d= -f2- || true; }

# --- 3. secret -------------------------------------------------------------
if [ -z "$(get_env DJANGO_SECRET_KEY)" ]; then
  SECRET="$(python3 -c 'import secrets;print(secrets.token_urlsafe(64))')"
  set_env DJANGO_SECRET_KEY "$SECRET"
  log "已產生 Django SECRET_KEY"
fi
if [ -z "$(get_env POSTGRES_PASSWORD)" ] || [ "$(get_env POSTGRES_PASSWORD)" = "change-me-strong-db-password" ]; then
  set_env POSTGRES_PASSWORD "$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')"
  log "已產生資料庫密碼"
fi

# --- 4. admin credentials --------------------------------------------------
ADMIN_USER="${ADMIN_USERNAME:-$(get_env ADMIN_USERNAME)}"; ADMIN_USER="${ADMIN_USER:-admin}"
set_env ADMIN_USERNAME "$ADMIN_USER"
if [ -z "$(get_env ADMIN_PASSWORD)" ] && [ -z "${ADMIN_PASSWORD:-}" ]; then
  if [ -t 0 ]; then
    read -r -s -p "設定管理員密碼（留空則自動產生一次性密碼）： " ADMIN_PW; echo
  fi
  if [ -n "${ADMIN_PW:-}" ]; then
    set_env ADMIN_PASSWORD "$ADMIN_PW"
    log "已設定管理員密碼"
  else
    warn "未提供密碼：首次啟動時會在 web 容器日誌中列印一次性隨機密碼。"
  fi
fi

# --- 5. derive GHCR image names from git remote ----------------------------
REMOTE="$(git config --get remote.origin.url 2>/dev/null || true)"
if [ -n "$REMOTE" ]; then
  slug="$(echo "$REMOTE" | sed -E 's#(git@|https://)github.com[:/]##; s/\.git$//')"
  owner="$(echo "$slug" | cut -d/ -f1 | tr 'A-Z' 'a-z')"
  repo="$(echo "$slug" | cut -d/ -f2 | tr 'A-Z' 'a-z')"
  if [ -n "$owner" ] && [ -n "$repo" ]; then
    log "GHCR 映像前綴：ghcr.io/${owner}/${repo}-{app,scanner}"
  fi
fi

# --- 6. build or pull ------------------------------------------------------
MODE="${1:-}"
if [ -z "$MODE" ] && [ -t 0 ]; then
  read -r -p "映像模式 [1] 本地建置 (預設)  [2] 從 GHCR 拉取： " ans
  case "$ans" in 2) MODE=prebuilt ;; *) MODE=build ;; esac
fi
MODE="${MODE:-build}"

if [ "$MODE" = "prebuilt" ]; then
  log "拉取 GHCR 映像..."
  $DC -f compose.yml -f compose.prebuilt.yml pull
  COMPOSE_FILES="-f compose.yml -f compose.prebuilt.yml"
else
  log "本地建置 app 與 scanner 映像（scanner 建置可能需要數分鐘）..."
  $DC build
  $DC --profile scanner build scanner-build
  COMPOSE_FILES="-f compose.yml"
fi

# --- 7. start --------------------------------------------------------------
log "啟動相依服務與應用..."
# shellcheck disable=SC2086
$DC $COMPOSE_FILES up -d

WEB_PORT="$(get_env WEB_PORT)"; WEB_PORT="${WEB_PORT:-8080}"
cat <<EOF

$(printf '\033[32m[完成]\033[0m') KaliRecon Web 已啟動。

從 Windows 建立 SSH 通道：
  ssh -N -L ${WEB_PORT}:127.0.0.1:${WEB_PORT} <kali-user>@<kali-ip>

然後於瀏覽器開啟：
  http://127.0.0.1:${WEB_PORT}

管理員帳號：${ADMIN_USER}
$( [ -z "$(get_env ADMIN_PASSWORD)" ] && echo "（一次性密碼請查看：docker compose logs web | grep 一次性）" )

查看日誌：docker compose logs -f web worker
EOF
