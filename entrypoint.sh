#!/bin/bash
# ============================================
# VulnScan Server - Entrypoint
# ============================================
# .env 준비 → 서버 실행
# ============================================

set -e

# ── .env 파일 준비 ──
# docker-compose에서 env_file로 주입하지만,
# 단독 docker run 시에도 동작하도록 폴백
if [ ! -f /app/.env ]; then
    if [ -f /app/.env.example ]; then
        echo "[초기화] .env.example → .env 복사"
        cp /app/.env.example /app/.env
    fi
fi

# ── NVD 캐시 상태 표시 ──
if [ -f /app/data/nvd_cache.db ]; then
    SIZE=$(stat -c%s /app/data/nvd_cache.db 2>/dev/null || echo 0)
    SIZE_MB=$((SIZE / 1024 / 1024))
    echo "[시스템] NVD 캐시: ${SIZE_MB}MB 로드됨"
else
    echo "[시스템] NVD 캐시 없음 (첫 스캔 시 API로 다운로드됩니다)"
fi

# ── 서버 실행 ──
exec python -m uvicorn main:app \
    --host "${HOST:-0.0.0.0}" \
    --port "${PORT:-8000}" \
    --log-level warning \
    --no-access-log
