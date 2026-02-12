"""
Remote Scan API Router

원격 호스트 스캔을 위한 새로운 API 엔드포인트
기존 /api/scan/{host_id}와 호환성 유지하면서 확장
"""

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone, timedelta
import json
import asyncio
import logging

logger = logging.getLogger(__name__)

# KST timezone
KST = timezone(timedelta(hours=9))

from ..models.database import get_db
from ..models.schemas import Host, ScanJob, AssetSnapshot, AuditLog, ScanHistory, Finding, Package, CVE
from ..services.job_runner import (
    JobRunner, ScanPreset, ScanConfig, 
    get_job_runner, init_job_runner
)
from ..services.remote_scanner import RemoteScanner

router = APIRouter(prefix="/api/remote", tags=["remote-scan"])


# === Pydantic Models ===

class HostCreateRequest(BaseModel):
    """호스트 등록 요청"""
    hostname: str
    ip_address: str
    zone: str = "default"
    os_type: str = "linux"
    ssh_port: int = 22
    ssh_username: str = "root"
    auth_method: str = "key"  # key, password
    ssh_key_path: Optional[str] = None
    ssh_password: Optional[str] = None  # 비밀번호 인증용
    tags: Optional[str] = None
    owner: Optional[str] = None
    description: Optional[str] = None
    is_allowed: bool = True  # allowlist 등록 여부


class HostResponse(BaseModel):
    """호스트 응답"""
    id: int
    hostname: str
    ip_address: str
    zone: Optional[str] = "default"
    os_type: Optional[str] = "linux"
    os_version: Optional[str] = None
    ssh_port: Optional[int] = 22
    ssh_username: Optional[str] = "root"
    auth_method: Optional[str] = "key"
    is_allowed: Optional[bool] = True
    tags: Optional[str] = None
    owner: Optional[str] = None
    last_scan: Optional[datetime] = None
    last_discovery: Optional[datetime] = None
    distro_id: Optional[str] = None
    pkg_manager: Optional[str] = None
    arch: Optional[str] = None
    status: Optional[str] = "unknown"

    class Config:
        from_attributes = True


class ScanRequest(BaseModel):
    """스캔 요청"""
    host_id: Optional[int] = None  # body에서도 받을 수 있도록
    preset: str = "standard"  # fast, standard, deep
    categories: List[str] = ["all"]
    filter_patched: bool = True
    filter_old_cve: bool = True
    cve_years: Optional[int] = None  # CVE 검색 시작 년도 (예: 2024), None = 전체
    initiated_by: str = "api"


class ScanJobResponse(BaseModel):
    """스캔 작업 응답"""
    id: int  # job_id
    host_id: int
    status: Optional[str] = "pending"
    preset: Optional[str] = "standard"
    current_phase: Optional[str] = None  # phase
    progress_percent: Optional[int] = 0  # progress
    progress_message: Optional[str] = None  # message
    created_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None  # alias for completed_at (JS 호환성)
    packages_found: Optional[int] = 0
    cves_found: Optional[int] = 0
    findings_count: Optional[int] = 0  # for history display
    high_risk_count: Optional[int] = 0
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


class SnapshotResponse(BaseModel):
    """자산 스냅샷 응답"""
    id: int
    host_id: int
    created_at: datetime
    distro_id: Optional[str]
    pkg_manager: Optional[str]
    arch: Optional[str]
    kernel_version: Optional[str]
    is_busybox: bool
    has_systemd: bool
    packages_hash: Optional[str]
    collector_mode: Optional[str]
    confidence_discovery: Optional[str]

    class Config:
        from_attributes = True


# === Host Management Endpoints ===

@router.post("/hosts", response_model=HostResponse)
async def create_remote_host(
    request: HostCreateRequest,
    session: AsyncSession = Depends(get_db)
):
    """
    원격 호스트 등록 (allowlist에 추가)
    
    스캔 대상 호스트를 등록합니다. is_allowed=True여야 스캔 가능합니다.
    """
    # 중복 체크
    existing = await session.execute(
        select(Host).where(Host.hostname == request.hostname)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Host already exists")
    
    # 호스트 생성
    host = Host(
        hostname=request.hostname,
        ip_address=request.ip_address,
        zone=request.zone,
        os_type=request.os_type,
        ssh_port=request.ssh_port,
        ssh_username=request.ssh_username,
        auth_method=request.auth_method,
        ssh_key_path=request.ssh_key_path,
        ssh_password=request.ssh_password,  # 비밀번호 추가
        tags=request.tags,
        owner=request.owner,
        description=request.description,
        is_allowed=request.is_allowed,
    )
    session.add(host)
    
    # Audit log
    audit = AuditLog(
        actor=request.owner or "system",
        action="host_add",
        target_type="host",
        target_name=request.hostname,
        details=json.dumps(request.dict()),
        result="success"
    )
    session.add(audit)
    
    await session.commit()
    await session.refresh(host)
    
    return host


@router.get("/hosts", response_model=List[HostResponse])
async def list_remote_hosts(
    allowed_only: bool = Query(True, description="allowlist 호스트만 조회"),
    session: AsyncSession = Depends(get_db)
):
    """원격 호스트 목록 조회"""
    query = select(Host)
    if allowed_only:
        query = query.where(Host.is_allowed == True)
    
    result = await session.execute(query)
    return result.scalars().all()


@router.get("/hosts/{host_id}", response_model=HostResponse)
async def get_remote_host(
    host_id: int,
    session: AsyncSession = Depends(get_db)
):
    """원격 호스트 상세 조회"""
    result = await session.execute(select(Host).where(Host.id == host_id))
    host = result.scalar_one_or_none()
    
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    return host


@router.get("/hosts/{host_id}/findings")
async def get_host_findings(
    host_id: int,
    scan_id: Optional[int] = None,
    collector_mode: Optional[str] = Query(None, description="필터: os, kernel, local, binary"),
    session: AsyncSession = Depends(get_db)
):
    """호스트의 취약점 목록 조회 (기본: 최신 스캔 결과만)
    
    collector_mode 필터:
    - os: OS 패키지 CVE (커널 제외)
    - kernel: 커널 CVE
    - local: 로컬 스캔 CVE
    - binary: 바이너리 기반 CVE
    - 미지정: 전체
    """
    # 호스트 확인
    result = await session.execute(select(Host).where(Host.id == host_id))
    host = result.scalar_one_or_none()
    
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    # scan_id가 지정되지 않으면 최신 스캔만 조회
    if scan_id is None:
        latest_scan = await session.execute(
            select(ScanHistory)
            .where(ScanHistory.host_id == host_id)
            .order_by(ScanHistory.scan_started.desc())
            .limit(1)
        )
        latest = latest_scan.scalar_one_or_none()
        if latest:
            scan_id = latest.id
    
    # Finding 쿼리 + Package, CVE 조인
    query = (
        select(Finding, Package, CVE)
        .join(Package, Finding.package_id == Package.id)
        .join(CVE, Finding.cve_id == CVE.id)
        .where(Finding.host_id == host_id)
    )
    
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)
    
    # collector_mode 필터 적용
    if collector_mode:
        query = query.where(Finding.collector_mode == collector_mode)
    
    result = await session.execute(query.order_by(CVE.cvss_score.desc().nullslast(), CVE.cvss_v3_score.desc().nullslast()))
    rows = result.all()
    
    findings_list = []
    for finding, package, cve in rows:
        # CVSS 점수: 통합 cvss_score 우선, 없으면 v3 → v2 fallback (기존 데이터 호환)
        cvss_score = cve.cvss_score or cve.cvss_v3_score or cve.cvss_v2_score
        
        findings_list.append({
            "id": finding.id,
            "host_id": finding.host_id,
            "package_name": package.name,
            "package_version": package.version,
            "cve_id": cve.cve_id,
            "cvss_score": cvss_score,
            "cvss_version": cve.cvss_version,  # CVSS 버전 정보 추가
            "cvss_v4_score": cve.cvss_v4_score,  # v4
            "cvss_v3_score": cve.cvss_v3_score,  # v3
            "cvss_v2_score": cve.cvss_v2_score,  # v2
            "epss_score": cve.epss_score,
            "is_kev": cve.is_kev,
            "risk_level": finding.risk_level,
            "status": finding.status,
            "discovered_at": finding.discovered_at,
            "collector_mode": finding.collector_mode,
            "evidence": finding.evidence,
            "data_confidence": finding.data_confidence,
            "priority_score": finding.priority_score,
            "priority_level": finding.priority_level,
            "has_patch_available": finding.has_patch_available,
            "patch_version": finding.patch_version,
            # Package process information from Finding model
            "pkg_is_running": finding.pkg_is_running,
            "pkg_is_service": finding.pkg_is_service,
            "pkg_listening_ports": finding.pkg_listening_ports,
            "pkg_last_used": finding.pkg_last_used,
        })
    
    return findings_list


@router.get("/hosts/{host_id}/scan-history")
async def get_host_scan_history(
    host_id: int,
    limit: int = Query(20, le=100),
    session: AsyncSession = Depends(get_db)
):
    """호스트의 스캔 히스토리 목록 조회 (과거 스캔 결과 비교용)"""
    from sqlalchemy import func, case
    
    # 호스트 확인
    result = await session.execute(select(Host).where(Host.id == host_id))
    host = result.scalar_one_or_none()
    
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    # ScanHistory + Finding 개수 조회
    query = (
        select(
            ScanHistory,
            func.count(Finding.id).label("findings_count"),
            func.sum(case((CVE.cvss_v3_score >= 7.0, 1), else_=0)).label("high_risk_count")
        )
        .outerjoin(Finding, Finding.scan_id == ScanHistory.id)
        .outerjoin(CVE, Finding.cve_id == CVE.id)
        .where(ScanHistory.host_id == host_id)
        .group_by(ScanHistory.id)
        .order_by(ScanHistory.scan_started.desc())
        .limit(limit)
    )
    
    result = await session.execute(query)
    rows = result.all()
    
    history_list = []
    for scan, findings_count, high_risk_count in rows:
        history_list.append({
            "id": scan.id,
            "scan_started": scan.scan_started,
            "scan_completed": scan.scan_completed,
            "status": scan.status,
            "packages_found": scan.packages_found,
            "cves_found": findings_count or 0,  # 실제 Finding 개수
            "high_risk_count": high_risk_count or 0,
        })
    
    return {
        "host_id": host_id,
        "hostname": host.hostname,
        "total_scans": len(history_list),
        "scans": history_list
    }


@router.get("/hosts/{host_id}/compare")
async def compare_scan_results(
    host_id: int,
    scan1: int = Query(..., description="첫 번째 스캔 ID (이전 스캔)"),
    scan2: int = Query(..., description="두 번째 스캔 ID (현재/최신 스캔)"),
    session: AsyncSession = Depends(get_db)
):
    """두 스캔 결과 비교 (신규/해결/유지 취약점 분류)
    
    Returns:
        - new: scan2에만 존재하는 취약점 (신규 발견)
        - resolved: scan1에만 존재하는 취약점 (해결됨)
        - unchanged: 양쪽 모두 존재하는 취약점 (미해결)
        - summary: 전체 통계
    """
    # 호스트 확인
    result = await session.execute(select(Host).where(Host.id == host_id))
    host = result.scalar_one_or_none()
    
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    # 스캔 정보 조회
    scan1_result = await session.execute(
        select(ScanHistory).where(
            ScanHistory.id == scan1,
            ScanHistory.host_id == host_id
        )
    )
    scan1_info = scan1_result.scalar_one_or_none()
    if not scan1_info:
        raise HTTPException(status_code=404, detail=f"Scan {scan1} not found for host {host_id}")
    
    scan2_result = await session.execute(
        select(ScanHistory).where(
            ScanHistory.id == scan2,
            ScanHistory.host_id == host_id
        )
    )
    scan2_info = scan2_result.scalar_one_or_none()
    if not scan2_info:
        raise HTTPException(status_code=404, detail=f"Scan {scan2} not found for host {host_id}")
    
    # scan1 취약점 조회 (cve_id를 키로)
    query1 = (
        select(Finding, Package, CVE)
        .join(Package, Finding.package_id == Package.id)
        .join(CVE, Finding.cve_id == CVE.id)
        .where(Finding.scan_id == scan1)
    )
    result1 = await session.execute(query1)
    
    # scan2 취약점 조회
    query2 = (
        select(Finding, Package, CVE)
        .join(Package, Finding.package_id == Package.id)
        .join(CVE, Finding.cve_id == CVE.id)
        .where(Finding.scan_id == scan2)
    )
    result2 = await session.execute(query2)
    
    def to_dict(finding, package, cve):
        cvss_score = cve.cvss_v3_score or cve.cvss_v2_score or 0
        return {
            "id": finding.id,
            "package_name": package.name,
            "package_version": package.version,
            "cve_id": cve.cve_id,
            "cvss_score": cvss_score,
            "epss_score": cve.epss_score,
            "is_kev": cve.is_kev,
            "risk_level": finding.risk_level,
            "discovered_at": finding.discovered_at,
        }
    
    # 딕셔너리로 변환 (CVE ID를 키로)
    scan1_findings = {}
    for f, p, c in result1.all():
        key = (c.cve_id, p.name)  # CVE + 패키지명으로 식별
        scan1_findings[key] = to_dict(f, p, c)
    
    scan2_findings = {}
    for f, p, c in result2.all():
        key = (c.cve_id, p.name)
        scan2_findings[key] = to_dict(f, p, c)
    
    keys1 = set(scan1_findings.keys())
    keys2 = set(scan2_findings.keys())
    
    # 시간순으로 older/newer 결정
    scan1_time = scan1_info.scan_started or scan1_info.scan_completed
    scan2_time = scan2_info.scan_started or scan2_info.scan_completed
    
    if scan1_time and scan2_time and scan1_time > scan2_time:
        # scan1이 더 최신이면 swap
        scan1_info, scan2_info = scan2_info, scan1_info
        scan1_findings, scan2_findings = scan2_findings, scan1_findings
        keys1, keys2 = keys2, keys1
    
    # 분류 (older=scan1, newer=scan2 기준)
    new_keys = keys2 - keys1  # scan2에만 있음 (신규)
    resolved_keys = keys1 - keys2  # scan1에만 있음 (해결됨)
    unchanged_keys = keys1 & keys2  # 양쪽에 다 있음 (미해결)
    
    new_findings = [scan2_findings[k] for k in new_keys]
    resolved_findings = [scan1_findings[k] for k in resolved_keys]
    unchanged_findings = [scan2_findings[k] for k in unchanged_keys]
    
    # CVSS 점수 내림차순 정렬
    new_findings.sort(key=lambda x: x["cvss_score"] or 0, reverse=True)
    resolved_findings.sort(key=lambda x: x["cvss_score"] or 0, reverse=True)
    unchanged_findings.sort(key=lambda x: x["cvss_score"] or 0, reverse=True)
    
    # 통계 계산
    def count_high_risk(findings):
        return sum(1 for f in findings if (f["cvss_score"] or 0) >= 7.0)
    
    return {
        "host_id": host_id,
        "hostname": host.hostname,
        "scan_old": {
            "id": scan1_info.id,
            "scan_started": scan1_info.scan_started,
            "cves_found": len(scan1_findings),
        },
        "scan_new": {
            "id": scan2_info.id,
            "scan_started": scan2_info.scan_started,
            "cves_found": len(scan2_findings),
        },
        "summary": {
            "new_count": len(new_findings),
            "resolved_count": len(resolved_findings),
            "unchanged_count": len(unchanged_findings),
            "new_high_risk": count_high_risk(new_findings),
            "resolved_high_risk": count_high_risk(resolved_findings),
            "unchanged_high_risk": count_high_risk(unchanged_findings),
        },
        "new": new_findings,  # 신규 발견된 취약점
        "resolved": resolved_findings,  # 해결된 취약점
        "unchanged": unchanged_findings,  # 아직 남아있는 취약점
    }


@router.delete("/hosts/{host_id}")
async def delete_remote_host(
    host_id: int,
    session: AsyncSession = Depends(get_db)
):
    """원격 호스트 삭제"""
    result = await session.execute(select(Host).where(Host.id == host_id))
    host = result.scalar_one_or_none()
    
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    hostname = host.hostname
    
    # Audit log
    audit = AuditLog(
        actor="system",
        action="host_delete",
        target_type="host",
        target_id=host_id,
        target_name=hostname,
        result="success"
    )
    session.add(audit)
    
    await session.delete(host)
    await session.commit()
    
    return {"message": f"Host '{hostname}' deleted successfully", "host_id": host_id}


@router.put("/hosts/{host_id}")
async def update_remote_host(
    host_id: int,
    request: HostCreateRequest,
    session: AsyncSession = Depends(get_db)
):
    """원격 호스트 정보 수정"""
    result = await session.execute(select(Host).where(Host.id == host_id))
    host = result.scalar_one_or_none()
    
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    # 업데이트
    host.hostname = request.hostname
    host.ip_address = request.ip_address
    host.zone = request.zone
    host.os_type = request.os_type
    host.ssh_port = request.ssh_port
    host.ssh_username = request.ssh_username
    host.auth_method = request.auth_method
    host.ssh_key_path = request.ssh_key_path
    host.ssh_password = request.ssh_password
    host.tags = request.tags
    host.owner = request.owner
    host.description = request.description
    host.is_allowed = request.is_allowed
    
    # Audit log
    audit = AuditLog(
        actor="system",
        action="host_update",
        target_type="host",
        target_id=host_id,
        target_name=host.hostname,
        details=json.dumps(request.dict()),
        result="success"
    )
    session.add(audit)
    
    await session.commit()
    await session.refresh(host)
    
    return host


@router.patch("/hosts/{host_id}/allowlist")
async def toggle_host_allowlist(
    host_id: int,
    is_allowed: bool,
    session: AsyncSession = Depends(get_db)
):
    """호스트 allowlist 상태 변경"""
    result = await session.execute(select(Host).where(Host.id == host_id))
    host = result.scalar_one_or_none()
    
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    host.is_allowed = is_allowed
    
    # Audit log
    audit = AuditLog(
        actor="system",
        action="allowlist_change",
        target_type="host",
        target_id=host_id,
        target_name=host.hostname,
        details=json.dumps({"is_allowed": is_allowed}),
        result="success"
    )
    session.add(audit)
    
    await session.commit()
    
    return {
        "host_id": host_id,
        "hostname": host.hostname,
        "is_allowed": is_allowed,
        "message": f"Host {'added to' if is_allowed else 'removed from'} allowlist"
    }


# === Scan Endpoints ===

@router.post("/scan")
async def start_remote_scan_from_body(
    request: ScanRequest,
    background_tasks: BackgroundTasks = None,
    session: AsyncSession = Depends(get_db)
):
    """
    원격 호스트 스캔 시작 (body에서 host_id 받기)
    """
    if not request.host_id:
        raise HTTPException(status_code=400, detail="host_id is required")
    
    return await _start_scan_internal(request.host_id, request, background_tasks, session)


@router.post("/scan/{host_id}")
async def start_remote_scan(
    host_id: int,
    request: ScanRequest = None,
    background_tasks: BackgroundTasks = None,
    session: AsyncSession = Depends(get_db)
):
    """
    원격 호스트 스캔 시작 (path에서 host_id 받기)
    
    프리셋:
    - fast: 빠른 Discovery + 최소 수집 (10-30초)
    - standard: Discovery + 패키지 전체 + CVE 분석 (1-5분)
    - deep: 심층 분석 + 바이너리 버전 (5-15분)
    
    주의: 스캔 대상은 반드시 allowlist에 등록되어 있어야 합니다.
    """
    if request is None:
        request = ScanRequest()
    
    return await _start_scan_internal(host_id, request, background_tasks, session)


async def _start_scan_internal(
    host_id: int,
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    session: AsyncSession
):
    """스캔 시작 내부 구현"""
    # 호스트 조회 및 allowlist 검증
    result = await session.execute(select(Host).where(Host.id == host_id))
    host = result.scalar_one_or_none()
    
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    if not getattr(host, 'is_allowed', True):
        raise HTTPException(
            status_code=403,
            detail=f"Host '{host.hostname}' is not in allowlist. "
                   "스캔 대상은 반드시 allowlist에 등록되어야 합니다."
        )
    
    # 스캔 설정 생성
    try:
        preset = ScanPreset(request.preset)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid preset: {request.preset}")
    
    config = ScanConfig.from_preset(preset)
    config.categories = request.categories
    config.filter_patched = request.filter_patched
    config.filter_old_cve = request.filter_old_cve
    config.cve_years = request.cve_years
    
    # ScanJob 레코드 생성
    scan_job = ScanJob(
        host_id=host_id,
        status="pending",
        preset=request.preset,
        initiated_by=request.initiated_by,
    )
    session.add(scan_job)
    await session.flush()
    job_id = scan_job.id
    
    # Audit log
    audit = AuditLog(
        actor=request.initiated_by,
        action="scan_start",
        target_type="host",
        target_id=host_id,
        target_name=host.hostname,
        preset=request.preset,
        details=json.dumps({
            "preset": request.preset,
            "categories": request.categories,
            "filter_patched": request.filter_patched,
        }),
        result="pending"
    )
    session.add(audit)
    await session.commit()
    
    # 백그라운드에서 스캔 실행
    background_tasks.add_task(
        _run_scan_background,
        job_id,
        host_id,
        config
    )
    
    return {
        "job_id": job_id,
        "host_id": host_id,
        "hostname": host.hostname,
        "preset": request.preset,
        "status": "pending",
        "message": f"Scan job {job_id} created. Use GET /api/remote/jobs/{job_id} to check status."
    }


async def _run_scan_background(job_id: int, host_id: int, config: ScanConfig):
    """백그라운드 스캔 실행"""
    from ..models.database import async_session_maker
    
    async with async_session_maker() as session:
        try:
            # ScanJob 상태 업데이트
            result = await session.execute(
                select(ScanJob).where(ScanJob.id == job_id)
            )
            scan_job = result.scalar_one_or_none()
            
            if scan_job:
                scan_job.status = "running"
                scan_job.started_at = datetime.now(KST)
                await session.commit()
            
            # 스캔 실행
            scanner = RemoteScanner(host_id, config, session, job_id=job_id)
            
            # 진행 상황 콜백 설정 (실시간 업데이트)
            async def update_progress(phase: str, progress: int, message: str):
                # 백그라운드로 비동기 실행 (스캔 속도에 영향 없도록)
                async def _update():
                    max_retries = 3
                    for attempt in range(max_retries):
                        try:
                            # 별도 세션 사용 (동시성 문제 방지)
                            async with async_session_maker() as update_session:
                                # SQLite timeout 설정
                                from sqlalchemy import text
                                await update_session.execute(text("PRAGMA busy_timeout = 5000"))

                                result = await update_session.execute(
                                    select(ScanJob).where(ScanJob.id == job_id)
                                )
                                job = result.scalar_one_or_none()
                                if job:
                                    # 이미 완료된 상태면 업데이트하지 않음
                                    if job.progress_percent == 100:
                                        break
                                    # progress가 현재 DB 값보다 낮으면 무시 (레이스 컨디션 방지)
                                    if progress < job.progress_percent and phase != "complete":
                                        break
                                    job.current_phase = phase
                                    job.progress_percent = progress
                                    job.progress_message = message
                                    await update_session.commit()
                                break  # 성공
                        except Exception as e:
                            if attempt < max_retries - 1:
                                await asyncio.sleep(0.1 * (attempt + 1))  # 재시도 전 대기
                            # 마지막 시도에서도 실패하면 조용히 무시 (스캔은 계속)

                # 백그라운드 태스크로 실행 (await 하지 않음)
                import asyncio
                asyncio.create_task(_update())
            
            scanner.set_progress_callback(update_progress)
            scan_result = await scanner.run()
            
            # 백그라운드 progress 업데이트가 완료될 때까지 잠시 대기
            await asyncio.sleep(0.5)
            
            # 결과 저장 - 반드시 progress_percent = 100으로 설정
            if scan_job:
                result = await session.execute(
                    select(ScanJob).where(ScanJob.id == job_id)
                )
                scan_job = result.scalar_one_or_none()
                
                scan_job.status = "completed" if scan_result["success"] else "failed"
                scan_job.completed_at = datetime.now(KST)
                scan_job.current_phase = "complete"
                scan_job.progress_percent = 100  # 반드시 100%
                scan_job.progress_message = "Scan completed"  # 메시지도 업데이트
                scan_job.packages_found = scan_result.get("packages_scanned", 0)
                scan_job.cves_found = scan_result.get("cves_found", 0)
                scan_job.high_risk_count = scan_result.get("high_risk_count", 0)
                scan_job.scan_history_id = scan_result.get("scan_history_id")
                scan_job.snapshot_id = scan_result.get("snapshot_id")
                
                if scan_result.get("discovery"):
                    scan_job.discovery_result = json.dumps(scan_result["discovery"])
                
                if scan_result.get("errors"):
                    scan_job.error_message = "; ".join(scan_result["errors"])
                
                await session.commit()
                
                # 최종 확인을 위해 한번 더 100% 설정 (백그라운드 태스크 완료 대기 후)
                await asyncio.sleep(0.3)
                result = await session.execute(
                    select(ScanJob).where(ScanJob.id == job_id)
                )
                scan_job = result.scalar_one_or_none()
                if scan_job and scan_job.progress_percent != 100:
                    scan_job.progress_percent = 100
                    scan_job.current_phase = "complete"
                    scan_job.progress_message = "Scan completed"
                    await session.commit()
                
        except Exception as e:
            # 에러 처리
            result = await session.execute(
                select(ScanJob).where(ScanJob.id == job_id)
            )
            scan_job = result.scalar_one_or_none()
            
            if scan_job:
                scan_job.status = "failed"
                scan_job.completed_at = datetime.now(KST)
                scan_job.error_message = str(e)
                await session.commit()


@router.get("/jobs/{job_id}")
async def get_scan_job(
    job_id: int,
    session: AsyncSession = Depends(get_db)
):
    """스캔 작업 상태 조회"""
    result = await session.execute(
        select(ScanJob).where(ScanJob.id == job_id)
    )
    job = result.scalar_one_or_none()
    
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    
    # finished_at 추가 (JS 호환성)
    return {
        "id": job.id,
        "host_id": job.host_id,
        "status": job.status,
        "preset": job.preset,
        "current_phase": job.current_phase,
        "progress_percent": job.progress_percent,
        "progress_message": job.progress_message,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "finished_at": job.completed_at,  # alias
        "packages_found": job.packages_found,
        "cves_found": job.cves_found,
        "findings_count": job.cves_found,  # alias for history
        "high_risk_count": job.high_risk_count,
        "error_message": job.error_message,
        "scan_id": job.scan_history_id,  # ScanJob에 저장된 scan_history_id 사용
    }


@router.get("/jobs")
async def list_scan_jobs(
    host_id: Optional[int] = None,
    status: Optional[str] = None,
    limit: int = Query(50, le=200),
    session: AsyncSession = Depends(get_db)
):
    """스캔 작업 목록 조회"""
    query = select(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit)
    
    if host_id:
        query = query.where(ScanJob.host_id == host_id)
    if status:
        query = query.where(ScanJob.status == status)
    
    result = await session.execute(query)
    jobs = result.scalars().all()
    
    # finished_at 추가 (JS 호환성)
    return [
        {
            "id": job.id,
            "host_id": job.host_id,
            "status": job.status,
            "preset": job.preset,
            "current_phase": job.current_phase,
            "progress_percent": job.progress_percent,
            "progress_message": job.progress_message,
            "created_at": job.created_at,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "finished_at": job.completed_at,  # alias
            "packages_found": job.packages_found,
            "cves_found": job.cves_found,
            "findings_count": job.cves_found,  # alias for history
            "high_risk_count": job.high_risk_count,
            "error_message": job.error_message,
        }
        for job in jobs
    ]


@router.post("/jobs/{job_id}/cancel")
async def cancel_scan_job(
    job_id: int,
    session: AsyncSession = Depends(get_db)
):
    """스캔 작업 취소"""
    result = await session.execute(
        select(ScanJob).where(ScanJob.id == job_id)
    )
    job = result.scalar_one_or_none()
    
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    
    if job.status in ("completed", "failed", "cancelled"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel job with status '{job.status}'"
        )
    
    job.status = "cancelled"
    job.completed_at = datetime.now(KST)
    job.error_message = "Cancelled by user"
    
    # 연관된 ScanHistory도 취소 처리
    try:
        from ..models.schemas import ScanHistory
        scan_results = await session.execute(
            select(ScanHistory).where(
                ScanHistory.host_id == job.host_id,
                ScanHistory.status == "running"
            )
        )
        running_scans = scan_results.scalars().all()
        for scan in running_scans:
            scan.status = "cancelled"
            scan.scan_completed = datetime.now(KST)
    except Exception:
        pass  # ScanHistory 업데이트 실패해도 취소는 진행
    
    await session.commit()
    
    # JobRunner의 인메모리 상태도 업데이트
    try:
        from ..services.job_runner import get_job_runner
        runner = get_job_runner()
        await runner.cancel_job(job_id)
    except Exception:
        pass  # JobRunner 업데이트 실패해도 DB는 이미 취소됨
    
    return {"job_id": job_id, "status": "cancelled"}


@router.delete("/jobs/{job_id}")
async def delete_scan_job(
    job_id: int,
    session: AsyncSession = Depends(get_db)
):
    """스캔 작업 삭제"""
    result = await session.execute(
        select(ScanJob).where(ScanJob.id == job_id)
    )
    job = result.scalar_one_or_none()
    
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    
    await session.delete(job)
    await session.commit()
    
    return {"message": f"Job {job_id} deleted", "job_id": job_id}


# === Asset Snapshot Endpoints ===

@router.get("/snapshots/{host_id}", response_model=List[SnapshotResponse])
async def get_host_snapshots(
    host_id: int,
    limit: int = Query(10, le=50),
    session: AsyncSession = Depends(get_db)
):
    """호스트의 자산 스냅샷 목록 조회"""
    result = await session.execute(
        select(AssetSnapshot)
        .where(AssetSnapshot.host_id == host_id)
        .order_by(AssetSnapshot.created_at.desc())
        .limit(limit)
    )
    return result.scalars().all()


@router.get("/snapshots/{host_id}/latest")
async def get_latest_snapshot(
    host_id: int,
    session: AsyncSession = Depends(get_db)
):
    """호스트의 최신 스냅샷 상세 조회"""
    result = await session.execute(
        select(AssetSnapshot)
        .where(AssetSnapshot.host_id == host_id)
        .order_by(AssetSnapshot.created_at.desc())
        .limit(1)
    )
    snapshot = result.scalar_one_or_none()
    
    if not snapshot:
        raise HTTPException(status_code=404, detail="No snapshots found for this host")
    
    # 상세 정보 포함
    return {
        "id": snapshot.id,
        "host_id": snapshot.host_id,
        "created_at": snapshot.created_at,
        "os_family": snapshot.os_family,
        "distro_id": snapshot.distro_id,
        "distro_version": snapshot.distro_version,
        "pkg_manager": snapshot.pkg_manager,
        "arch": snapshot.arch,
        "kernel_version": snapshot.kernel_version,
        "is_busybox": snapshot.is_busybox,
        "has_systemd": snapshot.has_systemd,
        "capabilities": json.loads(snapshot.capabilities) if snapshot.capabilities else [],
        "confidence_discovery": snapshot.confidence_discovery,
        "packages_hash": snapshot.packages_hash,
        "binaries_hash": snapshot.binaries_hash,
        "collector_mode": snapshot.collector_mode,
        "collection_duration_sec": snapshot.collection_duration_sec,
        "packages_count": len(json.loads(snapshot.packages_json)) if snapshot.packages_json else 0,
        "binaries_count": len(json.loads(snapshot.binaries_json)) if snapshot.binaries_json else 0,
    }


# === Audit Log Endpoints ===

@router.get("/audit")
async def get_audit_logs(
    host_id: Optional[int] = None,
    action: Optional[str] = None,
    limit: int = Query(100, le=500),
    session: AsyncSession = Depends(get_db)
):
    """감사 로그 조회"""
    query = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
    
    if host_id:
        query = query.where(AuditLog.target_id == host_id)
    if action:
        query = query.where(AuditLog.action == action)
    
    result = await session.execute(query)
    logs = result.scalars().all()
    
    return [
        {
            "id": log.id,
            "timestamp": log.timestamp,
            "actor": log.actor,
            "action": log.action,
            "target_type": log.target_type,
            "target_id": log.target_id,
            "target_name": log.target_name,
            "preset": log.preset,
            "result": log.result,
        }
        for log in logs
    ]


# === Presets Info Endpoint ===

@router.get("/presets")
async def get_scan_presets():
    """스캔 프리셋 정보 조회"""
    return {
        "presets": [
            {
                "name": "fast",
                "description": "🚀 빠른 스캔: Discovery + 보안/시스템 패키지만",
                "estimated_time": "10-30초",
                "details": "패키지 매니저(apk/dpkg/rpm)로 보안 관련 패키지만 수집. 커널 정보 없음.",
                "collect_packages": True,
                "collect_binaries": False,
                "collect_kernel_info": False,
                "categories": ["security", "system"],
            },
            {
                "name": "standard",
                "description": "⚡ 표준 스캔: 모든 패키지 + 커널 정보 + CVE 매칭",
                "estimated_time": "1-5분",
                "details": "패키지 매니저로 전체 패키지 수집, 커널 버전 확인, CVE DB 매칭. 바이너리 분석 없음.",
                "collect_packages": True,
                "collect_binaries": False,
                "collect_kernel_info": True,
                "categories": ["all"],
            },
            {
                "name": "deep",
                "description": "🔍 심층 스캔: 바이너리 버전 분석 + 포트 스캔",
                "estimated_time": "5-15분",
                "details": "패키지 매니저 없는 바이너리도 버전 추출(openssl, nginx 등), 네트워크 포트 스캔 옵션.",
                "collect_packages": True,
                "collect_binaries": True,
                "collect_kernel_info": True,
                "categories": ["all"],
                "port_scan_option": True,
            },
        ]
    }


# === PDF Report Endpoint for Remote Scans ===

@router.get("/report/{host_id}/pdf")
async def get_remote_scan_pdf_report(
    host_id: int,
    job_id: Optional[int] = None,
    session: AsyncSession = Depends(get_db)
):
    """원격 스캔 결과 PDF 보고서 생성
    
    Args:
        host_id: 호스트 ID
        job_id: 특정 스캔 작업 ID (없으면 최신 스캔 결과)
    """
    from vulnscan.core.pdf_generator import VulnerabilityPDFGenerator
    from datetime import datetime
    from fastapi.responses import Response
    
    # Get host
    result = await session.execute(select(Host).where(Host.id == host_id))
    host = result.scalar_one_or_none()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    # Get latest snapshot
    snapshot_query = select(AssetSnapshot).where(
        AssetSnapshot.host_id == host_id
    ).order_by(AssetSnapshot.collected_at.desc())
    
    if job_id:
        snapshot_query = snapshot_query.where(AssetSnapshot.job_id == job_id)
    
    snapshot_result = await session.execute(snapshot_query.limit(1))
    snapshot = snapshot_result.scalar_one_or_none()
    
    # Get findings for this host
    findings_query = select(Finding).where(Finding.host_id == host_id)
    findings_result = await session.execute(findings_query)
    findings_list = findings_result.scalars().all()
    
    # Prepare data
    host_info = {
        "hostname": host.hostname,
        "ip_address": host.ip_address,
        "os_type": host.distro_id or host.os_type or "Unknown",
        "os_version": host.os_version or "",
    }
    
    # Calculate stats
    findings_data = []
    high_risk_count = 0
    unauthorized_count = 0
    
    for f in findings_list:
        finding_dict = {
            "package_name": f.package_name if hasattr(f, 'package_name') else "Unknown",
            "package_version": f.package_version if hasattr(f, 'package_version') else "",
            "cve_id": f.cve_id,
            "cvss_score": f.cvss_score,
            "risk_level": f.risk_level,
            "data_confidence": f.data_confidence,
            "collector_mode": f.collector_mode,
            "evidence": f.evidence,
        }
        findings_data.append(finding_dict)
        
        if f.cvss_score and f.cvss_score >= 7.0:
            high_risk_count += 1
        if f.is_unauthorized_access:
            unauthorized_count += 1
    
    dashboard_stats = {
        "total_findings": len(findings_data),
        "high_risk_count": high_risk_count,
        "unauthorized_count": unauthorized_count,
    }
    
    package_summary = {
        "total_packages": len(set(f.get("package_name") for f in findings_data))
    }
    
    # Scan config for report
    scan_config = {
        "scan_type": "remote",
        "preset": "standard",  # TODO: Get from job if available
        "overall_confidence": snapshot.discovery_confidence if snapshot else "unknown",
        "discovery_info": {
            "distro_id": host.distro_id,
            "pkg_manager": host.pkg_manager,
            "arch": host.arch,
            "kernel_version": host.kernel_version,
            "is_busybox": host.is_busybox,
            "has_systemd": host.has_systemd,
            "confidence": snapshot.discovery_confidence if snapshot else "unknown",
        } if host.distro_id else None,
    }
    
    # Generate PDF
    pdf_generator = VulnerabilityPDFGenerator()
    pdf_bytes = pdf_generator.generate_report(
        host_info=host_info,
        dashboard_stats=dashboard_stats,
        findings=findings_data,
        package_summary=package_summary,
        scan_config=scan_config
    )
    
    # Return PDF
    filename = f"remote_scan_report_{host.hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# === SBOM Generation Endpoint ===

@router.get("/sbom/{host_id}")
async def get_host_sbom(
    host_id: int,
    format: str = Query("json", regex="^(json|xml)$"),
    session: AsyncSession = Depends(get_db)
):
    """
    호스트의 SBOM(Software Bill of Materials) 생성
    
    Alpine 같은 경량 리눅스에서 유용:
    - OS/커널 정보 포함
    - CPE 자동 생성으로 CVE 매칭
    - CycloneDX 1.4 표준
    """
    from ..core.sbom_generator import generate_sbom_for_host
    
    try:
        sbom = await generate_sbom_for_host(session, host_id)

        if format == "json":
            return sbom
        else:
            # XML 변환은 추후 구현
            raise HTTPException(status_code=400, detail="XML format not yet supported")

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SBOM generation failed: {str(e)}")


# === NVD 데이터 다운로드 ===

class NVDDownloadRequest(BaseModel):
    """NVD 년도 범위 다운로드 요청"""
    start_year: int = Field(2026, ge=1999, le=2026, description="시작 년도 (기본값: 2026)")
    end_year: int = Field(2026, ge=1999, le=2026, description="종료 년도 (기본값: 2026)")


@router.post("/nvd/download-range")
async def download_nvd_range(
    request: NVDDownloadRequest,
    background_tasks: BackgroundTasks
):
    """
    년도 범위의 NVD CVE 데이터를 다운로드하여 캐시에 저장

    백그라운드 작업으로 실행되며, 완료까지 수십 분이 소요될 수 있음
    """
    from ..core.nvd_client import NVDClient
    import asyncio

    start_year = request.start_year
    end_year = request.end_year

    if start_year > end_year:
        raise HTTPException(status_code=400, detail="시작 년도는 종료 년도보다 작거나 같아야 합니다")

    # 전역 진행 상황 저장소 (간단한 메모리 저장)
    download_progress = {
        "status": "running",
        "current_year": start_year,
        "start_year": start_year,
        "end_year": end_year,
        "completed_years": 0,
        "total_years": end_year - start_year + 1,
        "total_cves": 0,
        "message": f"{start_year}년 다운로드 준비 중..."
    }
    
    # 전역 변수에 저장 (API에서 조회 가능)
    router.download_progress = download_progress

    async def download_task():
        """백그라운드 다운로드 작업"""
        try:
            nvd_client = NVDClient()
            total_cves = 0

            for year in range(start_year, end_year + 1):
                download_progress["current_year"] = year
                download_progress["message"] = f"{year}년 다운로드 중..."
                
                result = await nvd_client.download_year_data(year)
                
                total_cves += result.get("total", 0)
                download_progress["completed_years"] = year - start_year + 1
                download_progress["total_cves"] = total_cves
                download_progress["message"] = f"{year}년 완료 ({result.get('total', 0)}개 CVE)"

            # 다운로드 완료 후 자동으로 CPE 인덱스 빌드
            download_progress["message"] = "CPE 인덱스 구축 중... (스캔 속도 최적화)"
            index_stats = await nvd_client.build_cpe_index()
            
            download_progress["status"] = "completed"
            download_progress["message"] = f"전체 완료! {total_cves}개 CVE 다운로드, {index_stats['packages']}개 패키지 인덱싱됨"
            download_progress["index_stats"] = index_stats

            print(f"[NVD 범위 다운로드 완료] {start_year}-{end_year}: {total_cves}개 CVE, 인덱스: {index_stats['packages']}개 패키지")

        except Exception as e:
            download_progress["status"] = "failed"
            download_progress["message"] = f"오류: {str(e)}"
            print(f"[NVD 범위 다운로드 실패] {start_year}-{end_year}: {e}")

    # 백그라운드 태스크로 실행
    background_tasks.add_task(download_task)

    return {
        "status": "started",
        "start_year": start_year,
        "end_year": end_year,
        "message": f"{start_year}~{end_year}년 NVD 데이터 다운로드가 백그라운드에서 시작되었습니다."
    }


@router.get("/nvd/download-progress")
async def get_download_progress():
    """NVD 다운로드 진행 상황 조회"""
    if hasattr(router, 'download_progress'):
        return router.download_progress
    else:
        return {
            "status": "idle",
            "message": "다운로드 작업 없음"
        }


@router.get("/nvd/cache-stats")
async def get_nvd_cache_stats():
    """NVD 캐시 통계 조회"""
    from ..core.nvd_client import NVDClient
    import sqlite3

    nvd_client = NVDClient()

    try:
        conn = sqlite3.connect(nvd_client._cache_db_path)
        cursor = conn.execute("SELECT COUNT(*) FROM nvd_cache")
        total_cached = cursor.fetchone()[0]

        # 년도별 캐시 조회
        cursor = conn.execute(
            "SELECT keyword FROM nvd_cache WHERE keyword LIKE '__year_%__'"
        )
        year_caches = cursor.fetchall()
        years_cached = [row[0].replace("__year_", "").replace("__", "") for row in year_caches]

        conn.close()
        
        # 인덱스 상태 조회
        index_stats = nvd_client.get_index_stats()

        return {
            "total_cached_items": total_cached,
            "years_cached": sorted(years_cached),
            "cache_db_path": nvd_client._cache_db_path,
            "index_loaded": index_stats["loaded"],
            "index_packages": index_stats["packages"],
            "index_years": index_stats["years"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get cache stats: {str(e)}")


@router.get("/nvd/download-records")
async def get_nvd_download_records():
    """NVD 다운로드 기록 조회"""
    from ..core.nvd_client import NVDClient

    try:
        nvd_client = NVDClient()
        records = nvd_client.get_download_records()

        return {
            "records": records,
            "total_years": len(records)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get download records: {str(e)}")


@router.post("/nvd/build-index")
async def build_nvd_cpe_index():
    """
    CPE 인덱스 수동 빌드 (스캔 속도 최적화)
    
    다운로드된 CVE 데이터에서 패키지명 인덱스를 구축하여
    스캔 시 검색 속도를 10배 이상 향상시킵니다.
    
    - 스캔 전에 자동으로 빌드되지만, 수동으로도 빌드 가능
    - 인덱스는 메모리에 저장되어 서버 재시작 시 다시 빌드 필요
    """
    from ..core.nvd_client import NVDClient

    try:
        nvd_client = NVDClient()
        
        # 다운로드 기록 확인
        records = nvd_client.get_download_records()
        if not records:
            return {
                "status": "no_data",
                "message": "다운로드된 CVE 데이터가 없습니다. 먼저 NVD 데이터를 다운로드하세요."
            }
        
        # 인덱스 빌드
        stats = await nvd_client.build_cpe_index()
        
        return {
            "status": "completed",
            "message": f"CPE 인덱스 구축 완료: {stats['packages']}개 패키지, {stats['cves']}개 CVE",
            "stats": stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Index build failed: {str(e)}")


@router.get("/nvd/index-stats")
async def get_nvd_index_stats():
    """CPE 인덱스 상태 조회"""
    from ..core.nvd_client import NVDClient

    try:
        nvd_client = NVDClient()
        stats = nvd_client.get_index_stats()
        
        return {
            "loaded": stats["loaded"],
            "packages": stats["packages"],
            "years": stats["years"],
            "message": "인덱스 로드됨" if stats["loaded"] else "인덱스 미로드 (스캔 시 자동 빌드)"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get index stats: {str(e)}")


@router.delete("/nvd/year/{year}")
async def delete_nvd_year_data(year: int):
    """특정 년도의 NVD 데이터 삭제"""
    from ..core.nvd_client import NVDClient

    if year < 1999 or year > 2026:
        raise HTTPException(status_code=400, detail="Invalid year (must be 1999-2026)")

    try:
        nvd_client = NVDClient()
        success = nvd_client.delete_year_data(year)

        if success:
            return {
                "status": "deleted",
                "year": year,
                "message": f"{year}년 데이터가 삭제되었습니다."
            }
        else:
            raise HTTPException(status_code=500, detail=f"Failed to delete {year} data")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Delete failed: {str(e)}")


@router.get("/nvd/test-api/{year}")
async def test_nvd_api(year: int):
    """NVD API 직접 테스트 (디버깅용)"""
    import httpx

    start_date = f"{year}-01-01T00:00:00.000"
    end_date = f"{year}-01-31T23:59:59.999"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start_date}&pubEndDate={end_date}&resultsPerPage=10"

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url)

            if response.status_code == 200:
                data = response.json()
                return {
                    "status": "success",
                    "year": year,
                    "total_results": data.get("totalResults", 0),
                    "url": url,
                    "sample_cves": [v["cve"]["id"] for v in data.get("vulnerabilities", [])[:5]]
                }
            else:
                return {
                    "status": "error",
                    "year": year,
                    "status_code": response.status_code,
                    "url": url,
                    "error": response.text[:500]
                }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Test failed: {str(e)}")


# ==================== CVE Detail API ====================

@router.get("/cves/{cve_id}")
async def get_cve_detail(
    cve_id: str,
    session: AsyncSession = Depends(get_db)
):
    """
    CVE 상세 정보 조회 (EPSS, KEV 포함)
    EPSS/KEV 정보는 항상 최신 데이터로 조회
    """
    result = await session.execute(
        select(CVE).where(CVE.cve_id == cve_id)
    )
    cve = result.scalar_one_or_none()
    
    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    
    # 항상 최신 EPSS/KEV 정보 조회 (캐시 무시)
    from ..core.epss_client import EPSSClient
    from ..core.kev_client import KEVClient
    
    epss_client = EPSSClient()
    kev_client = KEVClient()
    
    # KEV 초기화
    await kev_client.initialize()
    
    # EPSS 조회 (캐시 무시, 최신 데이터)
    epss_data = await epss_client.get_epss_score(cve_id)
    if epss_data:
        cve.epss_score = epss_data.get("epss_score")
        cve.epss_percentile = epss_data.get("epss_percentile")
    
    # KEV 조회
    kev_info = kev_client.get_kev_info(cve_id)
    if kev_info:
        cve.is_kev = True
        cve.kev_date_added = kev_info.get("dateAdded")
        cve.kev_due_date = kev_info.get("dueDate")
        cve.kev_ransomware = kev_info.get("knownRansomwareCampaignUse") == "Known"
    else:
        cve.is_kev = False
    
    # DB 업데이트
    await session.commit()
    await session.refresh(cve)
    
    return {
        "cve_id": cve.cve_id,
        "description": cve.description,
        "published_date": cve.published_date.isoformat() if cve.published_date else None,
        "last_modified": cve.last_modified.isoformat() if cve.last_modified else None,
        # CVSS v3
        "cvss_v3_score": cve.cvss_v3_score,
        "cvss_v3_vector": cve.cvss_v3_vector,
        "cvss_v3_severity": cve.cvss_v3_severity,
        # CVSS v2
        "cvss_v2_score": cve.cvss_v2_score,
        "cvss_v2_vector": cve.cvss_v2_vector,
        "cvss_v2_severity": cve.cvss_v2_severity,
        # CVSS v4
        "cvss_v4_score": cve.cvss_v4_score,
        "cvss_v4_vector": cve.cvss_v4_vector,
        "cvss_v4_severity": cve.cvss_v4_severity,
        # CVSS 메트릭
        "attack_vector": cve.attack_vector,
        "attack_complexity": cve.attack_complexity,
        "privileges_required": cve.privileges_required,
        "user_interaction": cve.user_interaction,
        "scope": cve.scope,
        "confidentiality_impact": cve.confidentiality_impact,
        "integrity_impact": cve.integrity_impact,
        "availability_impact": cve.availability_impact,
        # CPE & References
        "cpe_list": cve.cpe_list,
        "references": cve.references,
        # EPSS (Exploit Prediction Score)
        "epss_score": cve.epss_score,
        "epss_percentile": cve.epss_percentile,
        # KEV (Known Exploited Vulnerabilities)
        "is_kev": cve.is_kev,
        "kev_date_added": cve.kev_date_added,
        "kev_due_date": cve.kev_due_date,
        "kev_ransomware": cve.kev_ransomware,
        # Exploit 정보
        "has_exploit": cve.has_exploit,
        "exploit_count": cve.exploit_count,
        "exploit_sources": cve.exploit_sources,
        "exploit_urls": cve.exploit_urls
    }


# ==================== Exploit/PoC API ====================

@router.get("/exploit/search/{cve_id}")
async def search_exploit(
    cve_id: str,
    use_cache: bool = Query(True, description="캐시 사용 여부"),
    session: AsyncSession = Depends(get_db)
):
    """
    CVE에 대한 Exploit/PoC 정보 검색
    
    - GitHub PoC (nomi-sec/PoC-in-GitHub)
    - Exploit-DB (searchsploit)
    """
    from ..core.exploit_client import get_exploit_client
    
    client = get_exploit_client()
    result = await client.search_exploits(cve_id, use_cache=use_cache)
    
    # DB에 exploit 정보 업데이트
    if result.get('has_exploit'):
        try:
            cve_result = await session.execute(
                select(CVE).where(CVE.cve_id == cve_id)
            )
            cve = cve_result.scalar_one_or_none()
            
            if cve:
                cve.has_exploit = True
                cve.exploit_count = result.get('exploit_count', 0)
                
                sources = []
                if result.get('github_pocs'):
                    sources.append('github')
                if result.get('exploitdb'):
                    sources.append('exploitdb')
                cve.exploit_sources = ','.join(sources)
                
                # URL 목록 저장
                urls = []
                for poc in result.get('github_pocs', [])[:5]:
                    urls.append({'source': 'github', 'url': poc.get('url', '')})
                for exp in result.get('exploitdb', [])[:5]:
                    urls.append({'source': 'exploitdb', 'url': exp.get('url', '')})
                cve.exploit_urls = json.dumps(urls)
                cve.exploit_last_checked = datetime.now(KST)
                
                await session.commit()
        except Exception as e:
            logger.error(f"Failed to update exploit info for {cve_id}: {e}")
    
    return result


@router.post("/exploit/batch-search")
async def batch_search_exploits(
    cve_ids: List[str],
    session: AsyncSession = Depends(get_db)
):
    """여러 CVE에 대한 Exploit 정보 일괄 검색"""
    from ..core.exploit_client import get_exploit_client
    
    if len(cve_ids) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 CVEs per request")
    
    client = get_exploit_client()
    results = await client.batch_search(cve_ids)
    
    # DB 일괄 업데이트
    updated_count = 0
    for cve_id, result in results.items():
        if result.get('has_exploit'):
            try:
                cve_result = await session.execute(
                    select(CVE).where(CVE.cve_id == cve_id)
                )
                cve = cve_result.scalar_one_or_none()
                
                if cve:
                    cve.has_exploit = True
                    cve.exploit_count = result.get('exploit_count', 0)
                    sources = []
                    if result.get('github_pocs'):
                        sources.append('github')
                    if result.get('exploitdb'):
                        sources.append('exploitdb')
                    cve.exploit_sources = ','.join(sources)
                    cve.exploit_last_checked = datetime.now(KST)
                    updated_count += 1
            except Exception as e:
                logger.error(f"Failed to update {cve_id}: {e}")
    
    await session.commit()
    
    return {
        "total_searched": len(cve_ids),
        "exploits_found": sum(1 for r in results.values() if r.get('has_exploit')),
        "db_updated": updated_count,
        "results": results
    }


@router.get("/exploit/check-tools")
async def check_exploit_tools():
    """PoC 실행에 필요한 도구 설치 여부 확인"""
    from ..core.exploit_client import get_poc_executor
    
    executor = get_poc_executor()
    tools = executor.check_prerequisites()
    
    recommendations = []
    if not tools.get('searchsploit'):
        recommendations.append("searchsploit: sudo apt install exploitdb")
    if not tools.get('nmap'):
        recommendations.append("nmap: sudo apt install nmap")
    if not tools.get('msfconsole'):
        recommendations.append("metasploit: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html")
    
    return {
        "tools": tools,
        "ready": all(tools.get(t) for t in ['python3', 'nmap', 'curl']),
        "full_ready": all(tools.values()),
        "recommendations": recommendations
    }


class PoCExecuteRequest(BaseModel):
    """PoC 실행 요청"""
    target_host: str
    target_port: int = 80
    poc_type: str = "nmap_vuln"  # github_poc, metasploit, nmap_vuln, manual
    poc_url: Optional[str] = None
    cve_id: Optional[str] = None
    dry_run: bool = True  # 기본: dry run (실제 실행 안 함)
    confirm: bool = False  # 실행 확인 (dry_run=False일 때 필수)


@router.post("/exploit/execute")
async def execute_poc(request: PoCExecuteRequest):
    """
    PoC/Exploit 실행 (안전 모드)
    
    ⚠️ 주의: 
    - 이 기능은 반드시 권한이 있는 테스트 환경에서만 사용하세요
    - 권한 없는 시스템에 대한 공격은 불법입니다
    - dry_run=True (기본값)은 명령어만 생성하고 실행하지 않습니다
    """
    from ..core.exploit_client import get_poc_executor
    
    # 실제 실행 시 확인 필수
    if not request.dry_run and not request.confirm:
        raise HTTPException(
            status_code=400, 
            detail="실제 실행을 위해서는 confirm=True가 필요합니다. 권한 있는 시스템에서만 사용하세요."
        )
    
    # localhost/내부망 체크 (외부 공격 방지)
    import ipaddress
    try:
        ip = ipaddress.ip_address(request.target_host)
        if not request.dry_run and ip.is_global:
            raise HTTPException(
                status_code=403,
                detail="외부 IP에 대한 실제 공격은 허용되지 않습니다. dry_run 모드를 사용하세요."
            )
    except ValueError:
        # 도메인인 경우
        if not request.dry_run and not request.target_host.endswith('.local'):
            raise HTTPException(
                status_code=403,
                detail="외부 도메인에 대한 실제 공격은 허용되지 않습니다."
            )
    
    executor = get_poc_executor()
    result = await executor.execute_poc(
        target_host=request.target_host,
        target_port=request.target_port,
        poc_type=request.poc_type,
        poc_url=request.poc_url or "",
        cve_id=request.cve_id or "",
        dry_run=request.dry_run
    )
    
    return result


@router.get("/exploit/log")
async def get_exploit_execution_log():
    """PoC 실행 로그 조회"""
    from ..core.exploit_client import get_poc_executor
    
    executor = get_poc_executor()
    return {
        "log": executor.get_execution_log(),
        "total": len(executor.get_execution_log())
    }


# 호스트별 exploit 조회 API
@router.get("/hosts/{host_id}/exploits")
async def get_host_exploits(
    host_id: int,
    refresh: bool = Query(False, description="강제 새로고침"),
    session: AsyncSession = Depends(get_db)
):
    """호스트의 취약점 중 Exploit이 존재하는 것들 조회"""
    from ..core.exploit_client import get_exploit_client
    
    # 호스트의 CVE 목록 조회
    result = await session.execute(
        select(Finding, CVE)
        .join(CVE, Finding.cve_id == CVE.id)
        .where(Finding.host_id == host_id)
    )
    rows = result.all()
    
    if not rows:
        return {"host_id": host_id, "exploits": [], "total": 0}
    
    # CVE ID 목록
    cve_ids = list(set(cve.cve_id for _, cve in rows))
    
    # Exploit 정보 조회 (refresh 시 캐시 무시)
    if refresh:
        client = get_exploit_client()
        exploit_results = await client.batch_search(cve_ids[:30])  # 최대 30개
    else:
        # DB에서 기존 exploit 정보 사용
        exploit_results = {}
        for _, cve in rows:
            if cve.has_exploit:
                exploit_results[cve.cve_id] = {
                    'cve_id': cve.cve_id,
                    'has_exploit': True,
                    'exploit_count': cve.exploit_count or 0,
                    'exploit_sources': cve.exploit_sources,
                    'exploit_urls': json.loads(cve.exploit_urls) if cve.exploit_urls else []
                }
    
    # Exploit이 있는 CVE만 필터링
    exploits_with_info = []
    for finding, cve in rows:
        cve_id = cve.cve_id
        if cve_id in exploit_results and exploit_results[cve_id].get('has_exploit'):
            exploits_with_info.append({
                'cve_id': cve_id,
                'cvss_score': cve.cvss_v3_score or cve.cvss_v2_score,
                'is_kev': cve.is_kev,
                'exploit_count': exploit_results[cve_id].get('exploit_count', 0),
                'exploit_sources': exploit_results[cve_id].get('exploit_sources', ''),
                'github_pocs': exploit_results[cve_id].get('github_pocs', [])[:3],
                'exploitdb': exploit_results[cve_id].get('exploitdb', [])[:3],
            })
    
    # CVSS 점수 순으로 정렬
    exploits_with_info.sort(key=lambda x: x.get('cvss_score') or 0, reverse=True)
    
    return {
        "host_id": host_id,
        "total_cves": len(cve_ids),
        "exploits_found": len(exploits_with_info),
        "exploits": exploits_with_info
    }


@router.post("/exploit/refresh-csv")
async def refresh_exploitdb_csv():
    """
    Exploit-DB CSV 캐시 강제 갱신
    
    GitLab에서 최신 CSV 파일을 다운로드하여 메모리 캐시를 갱신합니다.
    정기적으로 실행하여 최신 Exploit 정보를 유지할 수 있습니다.
    """
    from ..core.exploit_client import get_exploit_client
    
    client = get_exploit_client()
    
    # 기존 캐시 정보
    old_count = len(client.exploitdb_csv_cache)
    old_timestamp = client.exploitdb_csv_timestamp
    
    # CSV 강제 갱신
    success = await client._load_exploitdb_csv(force_refresh=True)
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to refresh Exploit-DB CSV")
    
    new_count = len(client.exploitdb_csv_cache)
    new_timestamp = client.exploitdb_csv_timestamp
    
    return {
        "status": "success",
        "message": "Exploit-DB CSV refreshed successfully",
        "old_cache": {
            "cve_count": old_count,
            "timestamp": old_timestamp
        },
        "new_cache": {
            "cve_count": new_count,
            "timestamp": new_timestamp
        },
        "diff": new_count - old_count
    }


@router.get("/exploit/csv-status")
async def get_exploitdb_csv_status():
    """
    Exploit-DB CSV 캐시 상태 조회
    
    현재 메모리에 로드된 CSV 캐시의 상태를 확인합니다.
    """
    from ..core.exploit_client import get_exploit_client
    
    client = get_exploit_client()
    
    if not client.exploitdb_csv_cache or not client.exploitdb_csv_timestamp:
        return {
            "status": "not_loaded",
            "message": "CSV cache not loaded. It will be loaded automatically on first search.",
            "cve_count": 0,
            "timestamp": None
        }
    
    # 캐시 나이 계산
    from datetime import datetime
    age = datetime.now() - client.exploitdb_csv_timestamp
    age_hours = age.total_seconds() / 3600
    
    # 만료 여부
    is_expired = age_hours >= client.exploitdb_csv_ttl_hours
    
    return {
        "status": "loaded",
        "cve_count": len(client.exploitdb_csv_cache),
        "timestamp": client.exploitdb_csv_timestamp,
        "age_hours": round(age_hours, 1),
        "ttl_hours": client.exploitdb_csv_ttl_hours,
        "is_expired": is_expired,
        "message": "CSV cache is up-to-date" if not is_expired else "CSV cache expired, will refresh on next search"
    }

