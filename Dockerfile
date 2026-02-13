# ============================================
# VulnScan Server - Docker Image
# ============================================
# 경량 Python 이미지 기반 + SSH 원격 스캔 지원
# ============================================

FROM python:3.11-slim

LABEL maintainer="vulnscan"
LABEL description="Linux CVE Vulnerability Scanner (Agentless SSH)"

# ── 1) 시스템 패키지 설치 ──
# sshpass: 패스워드 방식 SSH 인증에 필요
# openssh-client: SSH 키 방식 원격 접속에 필요
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    sshpass \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# ── 2) 작업 디렉토리 ──
WORKDIR /app

# ── 3) Python 의존성 설치 (캐시 레이어 활용) ──
# requirements.txt가 변경되지 않으면 이 레이어는 캐시됨
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── 4) 소스 코드 복사 ──
COPY main.py .
COPY vulnscan/ ./vulnscan/
COPY static/ ./static/
COPY templates/ ./templates/
COPY .env.example .

# ── 5) 데이터 디렉토리 생성 ──
RUN mkdir -p /app/data /app/vulnscan/cache

# ── 6) 캐시 데이터 복사 (선택적) ──
# Git LFS 파일이 없으면 와일드카드로 스킵됨
# 빌드 컨텍스트에 있으면 복사, 없으면 무시
COPY nvd_cache.db* /app/data/
COPY kev_cache.json* /app/
COPY exploit_cache.json* /app/
COPY debian_security_cache.json* /app/
COPY ubuntu_security_cache.json* /app/

# ── 6-1) LFS 포인터 파일 제거 (깨진 파일 방지) ──
# Git LFS 미설치 시 포인터 텍스트(~130B)만 받아짐 → SQLite 에러 원인
RUN if [ -f /app/data/nvd_cache.db ] && [ $(stat -c%s /app/data/nvd_cache.db) -lt 10000 ]; then \
      echo "[경고] nvd_cache.db가 LFS 포인터입니다. 삭제합니다."; \
      rm -f /app/data/nvd_cache.db; \
    fi && \
    for cache in kev_cache.json exploit_cache.json debian_security_cache.json ubuntu_security_cache.json; do \
      if [ -f /app/$cache ] && [ $(stat -c%s /app/$cache) -lt 1000 ]; then \
        echo "[경고] $cache가 LFS 포인터입니다. 삭제합니다."; \
        rm -f /app/$cache; \
      fi; \
    done

# ── 7) entrypoint 스크립트 ──
COPY --chmod=755 entrypoint.sh /app/entrypoint.sh

# ── 8) 환경변수 기본값 ──
ENV HOST=0.0.0.0
ENV PORT=8000
ENV DATA_DIR=/app/data

# ── 9) 포트 노출 ──
EXPOSE 8000

# ── 10) 헬스체크 ──
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/docs')" || exit 1

# ── 11) 서버 실행 ──
ENTRYPOINT ["/app/entrypoint.sh"]
