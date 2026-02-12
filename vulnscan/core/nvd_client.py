import httpx
import asyncio
import sqlite3
import json
from typing import Optional, Dict, List
from datetime import datetime
import os
import time


class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None, verbose: bool = True):
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.verbose = verbose
        self.headers = {
            "User-Agent": "VulnScanner/1.0 (Python/httpx)"
        }
        if self.api_key and self.api_key.strip() and self.api_key != "여기에_NVD_API_키_입력":
            self.headers["apiKey"] = self.api_key
        else:
            self.api_key = None

        # Rate limiting settings (NVD 공식 제한 준수)
        # API 키 없음: 30초당 5회 = 6초당 1회
        # API 키 있음: 30초당 50회 = 0.6초당 1회
        # 다운로드 시에는 더 빠르게 (안전 마진 50%)
        self.rate_limit_delay = 0.6 if self.api_key else 6.5
        self.download_delay = 0.3 if self.api_key else 6.5  # 다운로드 전용

        # Semaphore: 동시 요청 (rate limit 방지)
        max_concurrent = 5 if self.api_key else 1
        self._semaphore = asyncio.Semaphore(max_concurrent)

        # Track 429 errors for dynamic rate limiting
        self._rate_limit_hits = 0

        # SQLite 영속 캐시 설정
        self._cache_ttl = 86400  # 24 hours
        _data_dir = os.getenv("DATA_DIR", ".")
        self._cache_db_path = os.path.join(_data_dir, "nvd_cache.db")
        self._init_cache_db()
        
        # 메모리 캐시 (년도별 CVE 데이터) - 속도 향상용
        self._memory_cache = {}  # {year: [cves...]}
        
        # CPE 인덱스 (패키지명 → CVE 리스트) - 초고속 검색용
        self._cpe_index = {}  # {package_name: [cve_data...]}
        self._cpe_index_loaded = False
        self._cpe_index_years = set()  # 인덱스에 로드된 년도
        
        # API 스킵 경고 플래그 (스캔당 한 번만 출력)
        self._api_skip_warned = False

        print(f"NVD API 초기화: {'API 키 사용' if self.api_key else 'API 키 없음'}, 동시 요청: {max_concurrent}개, Delay: {self.rate_limit_delay}초, 캐시: SQLite 영속", flush=True)

    def _init_cache_db(self):
        """SQLite 캐시 DB 초기화 및 자동 정리"""
        conn = sqlite3.connect(self._cache_db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS nvd_cache (
                keyword TEXT PRIMARY KEY,
                cves TEXT,
                timestamp REAL
            )
        """)
        conn.commit()
        
        # 오래된 캐시 삭제 (24시간 이상) - 단, 년도별 영구 데이터(__year_)는 보존
        cutoff = time.time() - self._cache_ttl
        cursor = conn.execute("DELETE FROM nvd_cache WHERE timestamp < ? AND keyword NOT LIKE '__year_%'", (cutoff,))
        deleted = cursor.rowcount
        
        # 레코드 수 확인
        cursor = conn.execute("SELECT COUNT(*) FROM nvd_cache")
        total = cursor.fetchone()[0]
        
        # 1000개 이상이면 VACUUM (공간 회수)
        if total > 1000 or deleted > 100:
            conn.execute("VACUUM")
            
        conn.commit()
        conn.close()

    def _get_cached(self, keyword: str) -> Optional[List[Dict]]:
        """캐시에서 조회 (datetime 문자열 복원)"""
        conn = sqlite3.connect(self._cache_db_path)
        cursor = conn.execute(
            "SELECT cves, timestamp FROM nvd_cache WHERE keyword = ?",
            (keyword.lower(),)
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            cves_json, timestamp = row
            if time.time() - timestamp < self._cache_ttl:
                cves = json.loads(cves_json)
                # datetime 문자열을 다시 datetime 객체로 변환
                for cve in cves:
                    for key in ["published_date", "last_modified"]:
                        if cve.get(key) and isinstance(cve[key], str):
                            try:
                                cve[key] = datetime.fromisoformat(cve[key])
                            except:
                                cve[key] = None
                return cves
        return None

    def _set_cached(self, keyword: str, cves: List[Dict]):
        """캐시에 저장 (datetime을 문자열로 변환)"""
        # datetime 객체를 JSON 직렬화 가능하게 변환
        def serialize(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            return obj

        cves_serializable = []
        for cve in cves:
            cve_copy = {}
            for k, v in cve.items():
                cve_copy[k] = serialize(v)
            cves_serializable.append(cve_copy)

        conn = sqlite3.connect(self._cache_db_path)
        conn.execute(
            "INSERT OR REPLACE INTO nvd_cache (keyword, cves, timestamp) VALUES (?, ?, ?)",
            (keyword.lower(), json.dumps(cves_serializable), time.time())
        )
        conn.commit()
        conn.close()

    def _set_cached_batch(self, items: List[tuple]):
        """배치로 캐시에 저장 (성능 개선)"""
        def serialize(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            return obj

        conn = sqlite3.connect(self._cache_db_path)

        for keyword, cves in items:
            cves_serializable = []
            for cve in cves:
                cve_copy = {}
                for k, v in cve.items():
                    cve_copy[k] = serialize(v)
                cves_serializable.append(cve_copy)

            conn.execute(
                "INSERT OR REPLACE INTO nvd_cache (keyword, cves, timestamp) VALUES (?, ?, ?)",
                (keyword.lower(), json.dumps(cves_serializable), time.time())
            )

        conn.commit()
        conn.close()

    async def search_cve_by_cpe(self, cpe_name: str) -> List[Dict]:
        """Search CVEs by CPE name"""
        params = {
            "cpeName": cpe_name
        }
        return await self._make_request(params)
    
    async def search_by_cpe(
        self, 
        cpe: str, 
        pub_start_date: Optional[tuple] = None,
        results_per_page: int = 100
    ) -> List[Dict]:
        """
        Search CVEs by CPE with date filtering
        
        Args:
            cpe: CPE 2.3 string (e.g., 'cpe:2.3:o:alpinelinux:alpine_linux:3.23.2')
            pub_start_date: (year, month, day) tuple for filtering
            results_per_page: Max results to return
        
        Returns:
            List of CVE dictionaries
        """
        params = {
            "cpeName": cpe,
            "resultsPerPage": min(results_per_page, 2000)
        }
        
        # Add date filter if provided
        if pub_start_date:
            year, month, day = pub_start_date
            start_date = datetime(year, month, day).isoformat() + 'Z'
            params["pubStartDate"] = start_date
        
        return await self._make_request(params)

    async def search_cve_by_keyword(self, keyword: str, cve_years: Optional[int] = None) -> List[Dict]:
        """Search CVEs by keyword (package name) with SQLite caching
        
        Args:
            keyword: 검색 키워드
            cve_years: 시작 년도 (예: 2022 = 2022년 이후 CVE만 반환), None = 전체 기간
        
        Note: NVD API에 날짜 필터를 보내지 않고, 결과를 가져온 후 클라이언트에서 필터링합니다.
              (NVD pubStartDate 파라미터가 불안정하여 결과가 누락되는 문제 방지)
        """
        # 캐시는 키워드 기준으로만 (날짜 필터는 결과에서 적용)
        cache_key = keyword
        
        # Check cache first (단, 빈 결과는 재검색)
        cached = self._get_cached(cache_key)
        if cached is not None and len(cached) > 0:
            # 캐시된 결과에 날짜 필터 적용
            if cve_years:
                filtered_by_year = self._filter_by_year(cached, cve_years)
                print(f"[캐시] {keyword}: {len(cached)}개 중 {cve_years}년+ {len(filtered_by_year)}개")
                return filtered_by_year
            print(f"[캐시] {keyword}: {len(cached)}개")
            return cached

        # 로컬 다운로드 데이터 확인
        local_records = self.get_download_records()
        local_years = {r['year'] for r in local_records}
        
        # 로컬 데이터가 있으면 하이브리드 모드
        if local_years:
            if cve_years:
                # 특정 년도부터 검색
                return await self._search_hybrid(keyword, cve_years)
            else:
                # 전체 기간: 로컬에 있는 모든 년도 검색 (로그 최소화)
                from datetime import datetime
                min_year = min(local_years)
                return await self._search_hybrid(keyword, min_year)

        # 로컬 데이터 없음 - 순수 API 호출
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 100
        }

        print(f"[API] {keyword}")
        results = await self._make_request(params)

        # CVSS >= 4.0 필터링
        filtered_results = []
        for cve in results:
            cvss_score = cve.get("cvss_v3_score") or 0.0
            if cvss_score >= 4.0:
                filtered_results.append(cve)

        print(f"[결과] {keyword}: {len(results)}개 → {len(filtered_results)}개")
        self._set_cached(cache_key, filtered_results)
        
        # 날짜 필터 적용 (cve_years 있을 때만)
        if cve_years:
            filtered_by_year = self._filter_by_year(filtered_results, cve_years)
            return filtered_by_year
        
        return filtered_results

    async def _search_hybrid(self, keyword: str, start_year) -> List[Dict]:
        """하이브리드 검색: CPE 인덱스 우선, 로컬 데이터 있으면 API 스킵 (성능 최적화)"""
        from datetime import datetime, date
        
        # start_year를 정수로 변환
        start_year = self._parse_cve_years(start_year)
        
        current_year = datetime.now().year
        today = date.today()
        all_results = []
        
        # 다운로드된 년도 확인
        local_records = self.get_download_records()
        local_years = {r['year'] for r in local_records}
        
        years_needed = list(range(start_year, current_year + 1))
        local_avail = [y for y in years_needed if y in local_years]
        api_needed = [y for y in years_needed if y not in local_years and y <= current_year]
        
        # 1. CPE 인덱스에서 빠른 검색 (인덱스가 로드되어 있으면)
        if local_avail and self._cpe_index_loaded:
            # 인덱스에 없는 년도가 있으면 먼저 로드
            missing_years = set(local_avail) - self._cpe_index_years
            if missing_years:
                await self._load_cpe_index(list(missing_years))
            
            # 인덱스에서 빠른 검색
            local_results = self._search_from_index(keyword, start_year)
            all_results.extend(local_results)
        elif local_avail:
            # 인덱스가 없으면 기존 방식 (첫 스캔 시)
            local_results = self._search_local_years(keyword, local_avail)
            all_results.extend(local_results)
        
        # 2. API 호출 스킵 정책:
        #    - 로컬 데이터가 있으면 API 호출 안 함 (성능 우선)
        #    - 최신 CVE가 필요하면 먼저 해당 년도를 다운로드하세요
        #    - 로컬 데이터가 전혀 없을 때만 API 호출
        if api_needed and not local_avail:
            # 로컬 데이터가 전혀 없을 때만 API 호출
            api_results = await self._search_api_years(keyword, api_needed)
            all_results.extend(api_results)
        elif api_needed and not self._api_skip_warned:
            # 첫 번째 패키지에서만 경고 (한 번만)
            self._api_skip_warned = True
            print(f"[최적화] {api_needed}년 데이터 미다운로드 → API 호출 스킵 (로컬 데이터로만 스캔)")
            print(f"         최신 CVE가 필요하면 해당 년도를 먼저 다운로드하세요.")
        
        # 로그는 결과가 있을 때만 출력
        if len(all_results) > 0:
            print(f"[발견] {keyword}: {len(all_results)}개 CVE")
        
        return all_results
    
    async def build_cpe_index(self, years: List[int] = None, progress_callback=None) -> Dict:
        """
        CPE 인덱스 구축 - 스캔 전에 한 번 실행하면 검색 속도 10배 이상 향상
        
        Args:
            years: 인덱스할 년도 리스트 (None이면 다운로드된 모든 년도)
            progress_callback: 진행상황 콜백 함수
        
        Returns:
            Dict: 인덱스 통계 {"packages": int, "cves": int, "years": list}
        """
        import time
        start_time = time.time()
        
        # 다운로드된 년도 확인
        local_records = self.get_download_records()
        if years is None:
            years = [r['year'] for r in local_records]
        
        if not years:
            print("[인덱스] 다운로드된 데이터가 없습니다. 먼저 download_year_data를 실행하세요.")
            return {"packages": 0, "cves": 0, "years": []}
        
        print(f"[인덱스] CPE 인덱스 구축 중... ({len(years)}년)")
        
        # 인덱스 초기화
        self._cpe_index = {}
        total_cves = 0
        
        for idx, year in enumerate(sorted(years)):
            if progress_callback:
                await progress_callback(idx, len(years), f"{year}년 처리 중...")
            
            # 년도별 CVE 데이터 로드
            cves = self._load_year_data(year)
            if not cves:
                continue
            
            # 각 CVE의 CPE에서 패키지명 추출하여 인덱스 구축
            for cve in cves:
                # CVSS 필터 (4.0 미만은 인덱스에서 제외)
                cvss_score = cve.get("cvss_v3_score") or cve.get("cvss_v2_score") or 0
                if cvss_score < 4.0:
                    continue
                
                cpe_list = cve.get("cpe_list", "")
                if not cpe_list:
                    continue
                
                # CPE에서 패키지명 추출
                package_names = self._extract_package_names_from_cpe(cpe_list)
                
                for pkg_name in package_names:
                    if pkg_name not in self._cpe_index:
                        self._cpe_index[pkg_name] = []
                    self._cpe_index[pkg_name].append(cve)
                
                total_cves += 1
            
            self._cpe_index_years.add(year)
            print(f"  {year}년: {len(cves)}개 CVE 인덱싱 완료")
        
        self._cpe_index_loaded = True
        
        elapsed = time.time() - start_time
        stats = {
            "packages": len(self._cpe_index),
            "cves": total_cves,
            "years": sorted(self._cpe_index_years),
            "elapsed_seconds": round(elapsed, 2)
        }
        
        print(f"[인덱스] 구축 완료: {stats['packages']}개 패키지, {stats['cves']}개 CVE, {elapsed:.1f}초")
        
        return stats
    
    def _extract_package_names_from_cpe(self, cpe_list: str) -> set:
        """CPE 문자열에서 패키지명 추출"""
        package_names = set()
        
        for cpe in cpe_list.split("|"):
            # CPE format: cpe:2.3:a:vendor:product:version...
            parts = cpe.lower().split(":")
            if len(parts) >= 5:
                product = parts[4]
                if product and len(product) >= 2:
                    package_names.add(product)
                    # 언더스코어/하이픈 변환 버전도 추가
                    package_names.add(product.replace("_", "-"))
                    package_names.add(product.replace("-", "_"))
        
        return package_names
    
    def _search_from_index(self, keyword: str, start_year: int = None) -> List[Dict]:
        """CPE 인덱스에서 빠른 검색 (O(1) 조회)"""
        keyword_lower = keyword.lower()
        results = []
        seen_cve_ids = set()
        
        # 직접 매칭
        if keyword_lower in self._cpe_index:
            for cve in self._cpe_index[keyword_lower]:
                cve_id = cve.get("cve_id")
                if cve_id not in seen_cve_ids:
                    # 년도 필터
                    if start_year:
                        pub_date = cve.get("published_date")
                        if pub_date:
                            try:
                                if isinstance(pub_date, str):
                                    pub_year = int(pub_date[:4])
                                else:
                                    pub_year = pub_date.year
                                if pub_year < start_year:
                                    continue
                            except:
                                pass
                    
                    # datetime 복원
                    cve_copy = dict(cve)
                    for key in ["published_date", "last_modified"]:
                        if cve_copy.get(key) and isinstance(cve_copy[key], str):
                            try:
                                cve_copy[key] = datetime.fromisoformat(cve_copy[key])
                            except:
                                cve_copy[key] = None
                    
                    results.append(cve_copy)
                    seen_cve_ids.add(cve_id)
        
        # 변형 이름으로도 검색 (하이픈/언더스코어 변환)
        variants = [
            keyword_lower.replace("-", "_"),
            keyword_lower.replace("_", "-")
        ]
        
        for variant in variants:
            if variant != keyword_lower and variant in self._cpe_index:
                for cve in self._cpe_index[variant]:
                    cve_id = cve.get("cve_id")
                    if cve_id not in seen_cve_ids:
                        # 년도 필터
                        if start_year:
                            pub_date = cve.get("published_date")
                            if pub_date:
                                try:
                                    if isinstance(pub_date, str):
                                        pub_year = int(pub_date[:4])
                                    else:
                                        pub_year = pub_date.year
                                    if pub_year < start_year:
                                        continue
                                except:
                                    pass
                        
                        cve_copy = dict(cve)
                        for key in ["published_date", "last_modified"]:
                            if cve_copy.get(key) and isinstance(cve_copy[key], str):
                                try:
                                    cve_copy[key] = datetime.fromisoformat(cve_copy[key])
                                except:
                                    cve_copy[key] = None
                        
                        results.append(cve_copy)
                        seen_cve_ids.add(cve_id)
        
        return results
    
    def search_packages_batch(self, package_names: List[str], start_year: int = None) -> Dict[str, List[Dict]]:
        """
        여러 패키지의 CVE를 한 번에 검색 (초고속 배치 처리)
        
        인덱스가 로드되어 있어야 함 (build_cpe_index 먼저 실행)
        
        Args:
            package_names: 검색할 패키지명 리스트
            start_year: 시작 년도 필터 (선택)
        
        Returns:
            Dict[str, List[Dict]]: {패키지명: [CVE 리스트]}
        """
        if not self._cpe_index_loaded:
            print("[경고] CPE 인덱스가 로드되지 않았습니다. build_cpe_index()를 먼저 실행하세요.")
            return {}
        
        results = {}
        
        for pkg_name in package_names:
            cves = self._search_from_index(pkg_name, start_year)
            if cves:
                results[pkg_name] = cves
        
        return results
    
    async def _load_cpe_index(self, years: List[int]):
        """추가 년도를 CPE 인덱스에 로드"""
        for year in years:
            if year in self._cpe_index_years:
                continue
            
            cves = self._load_year_data(year)
            if not cves:
                continue
            
            for cve in cves:
                cvss_score = cve.get("cvss_v3_score") or cve.get("cvss_v2_score") or 0
                if cvss_score < 4.0:
                    continue
                
                cpe_list = cve.get("cpe_list", "")
                if not cpe_list:
                    continue
                
                package_names = self._extract_package_names_from_cpe(cpe_list)
                
                for pkg_name in package_names:
                    if pkg_name not in self._cpe_index:
                        self._cpe_index[pkg_name] = []
                    self._cpe_index[pkg_name].append(cve)
            
            self._cpe_index_years.add(year)
        
        self._cpe_index_loaded = True
    
    def _load_year_data(self, year: int) -> List[Dict]:
        """년도별 CVE 데이터 로드 (메모리 캐시 활용)"""
        # 메모리 캐시 확인
        if year in self._memory_cache:
            return self._memory_cache[year]
        
        # SQLite에서 로드
        conn = sqlite3.connect(self._cache_db_path)
        cache_key = f"__year_{year}__"
        cursor = conn.execute(
            "SELECT cves FROM nvd_cache WHERE keyword = ?",
            (cache_key,)
        )
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return []
        
        cves = json.loads(row[0])
        
        # 메모리 캐시에 저장
        self._memory_cache[year] = cves
        
        return cves
    
    def is_index_loaded(self) -> bool:
        """인덱스 로드 여부 확인"""
        return self._cpe_index_loaded
    
    def get_index_stats(self) -> Dict:
        """인덱스 통계 반환"""
        return {
            "loaded": self._cpe_index_loaded,
            "packages": len(self._cpe_index),
            "years": sorted(self._cpe_index_years)
        }
    
    def reset_scan_state(self):
        """스캔 시작 전 상태 초기화 (경고 플래그 등)"""
        self._api_skip_warned = False
    
    def _search_local_years(self, keyword: str, years: List[int]) -> List[Dict]:
        """로컬 다운로드 데이터에서 키워드 검색 (병렬 처리)"""
        from concurrent.futures import ThreadPoolExecutor
        from functools import partial
        
        keyword_lower = keyword.lower()
        
        # 병렬 처리로 년도별 검색 (I/O 바운드 작업, 워커 16개로 증가)
        with ThreadPoolExecutor(max_workers=16) as executor:
            search_fn = partial(self._search_single_year, keyword_lower)
            year_results = list(executor.map(search_fn, years))
        
        # 결과 병합
        all_results = []
        for year_cves in year_results:
            all_results.extend(year_cves)
        
        return all_results
    
    def _search_single_year(self, keyword_lower: str, year: int) -> List[Dict]:
        """단일 년도 로컬 검색 (병렬 처리용, CPE 기반 최적화)"""
        results = []
        
        # 1. 메모리 캐시 확인 (매우 빠름)
        if year in self._memory_cache:
            all_cves = self._memory_cache[year]
        else:
            # 2. SQLite에서 로드
            conn = sqlite3.connect(self._cache_db_path)
            cache_key = f"__year_{year}__"
            cursor = conn.execute(
                "SELECT cves FROM nvd_cache WHERE keyword = ?",
                (cache_key,)
            )
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return results
            
            cves_json = row[0]
            all_cves = json.loads(cves_json)
            
            # 메모리 캐시에 저장 (다음 검색 시 빠르게)
            self._memory_cache[year] = all_cves
        
        # 키워드 매칭 - CPE 기반 최적화 (description 검색 제거)
        for cve in all_cves:
            # CVSS 필터 먼저 (빠른 제외)
            cvss_v3_score = cve.get("cvss_v3_score")
            cvss_v2_score = cve.get("cvss_v2_score")
            
            # v3가 없고 v2가 있으면 v2 사용
            if not cvss_v3_score and cvss_v2_score:
                cvss_v3_score = cvss_v2_score
                cve["cvss_v3_score"] = cvss_v2_score
                if not cve.get("cvss_v3_severity"):
                    cve["cvss_v3_severity"] = cve.get("cvss_v2_severity", "UNKNOWN")
                if not cve.get("cvss_v3_vector"):
                    cve["cvss_v3_vector"] = cve.get("cvss_v2_vector", "")
            
            if not cvss_v3_score or cvss_v3_score < 4.0:
                continue
            
            # CPE 리스트에서만 검색 (description 검색 제거 - 속도 10배 향상)
            cpe_list = cve.get("cpe_list", "")
            if not cpe_list:
                continue
            
            cpe_list_lower = cpe_list.lower()
            
            # 키워드가 CPE에 있는지 확인 (빠른 문자열 검색)
            if keyword_lower not in cpe_list_lower:
                continue
            
            # datetime 복원 (필요한 것만)
            for key in ["published_date", "last_modified"]:
                if cve.get(key) and isinstance(cve[key], str):
                    try:
                        cve[key] = datetime.fromisoformat(cve[key])
                    except:
                        cve[key] = None
            results.append(cve)
        
        return results
    
    async def _search_api_years(self, keyword: str, years: List[int]) -> List[Dict]:
        """API에서 특정 년도 범위 검색 (404 에러 조용히 처리)"""
        if not years:
            return []
        
        from datetime import datetime, date
        
        # 현재 날짜 기준으로 미래 년도 제외
        today = date.today()
        current_year = today.year
        
        # 미래 년도 필터링 (2026년 이후 등)
        valid_years = [y for y in years if y <= current_year]
        if not valid_years:
            return []  # 모두 미래 년도면 API 호출 안 함
        
        # 년도 범위를 pubStartDate/pubEndDate로 변환
        start_year = min(valid_years)
        end_year = max(valid_years)
        
        # 현재 년도인 경우 오늘 날짜까지만 검색 (미래 날짜 404 방지)
        if end_year == current_year:
            end_date = today.strftime("%Y-%m-%dT23:59:59.999Z")
        else:
            end_date = f"{end_year}-12-31T23:59:59.999Z"
        
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 100,
            "pubStartDate": f"{start_year}-01-01T00:00:00.000Z",
            "pubEndDate": end_date
        }
        
        results = await self._make_request(params, silent_404=True)
        
        # CVSS 필터링
        filtered = []
        for cve in results:
            cvss_score = cve.get("cvss_v3_score") or 0.0
            if cvss_score >= 4.0:
                filtered.append(cve)
        
        return filtered
    
    def _filter_by_year(self, cves: List[Dict], start_year: int) -> List[Dict]:
        """CVE 리스트에서 특정 년도 이후 발행된 것만 필터링"""
        from datetime import datetime
        
        # start_year가 문자열이면 정수로 변환
        start_year = self._parse_cve_years(start_year)
        
        filtered = []
        for cve in cves:
            published_date = cve.get("published_date")
            if not published_date:
                continue
            try:
                if isinstance(published_date, str):
                    pub_date = datetime.fromisoformat(published_date.replace("Z", "+00:00"))
                else:
                    pub_date = published_date
                
                if pub_date.year >= start_year:
                    filtered.append(cve)
            except Exception:
                # 파싱 실패 시 포함
                filtered.append(cve)
        
        return filtered
    
    def _parse_cve_years(self, cve_years) -> int:
        """cve_years 파라미터를 정수 년도로 변환"""
        from datetime import datetime
        current_year = datetime.now().year
        
        if cve_years is None:
            return 1999  # 최소 년도
        
        if isinstance(cve_years, int):
            return cve_years
        
        if isinstance(cve_years, str):
            # "최근 5년", "최근 3년" 등 파싱
            if "최근" in cve_years:
                import re
                match = re.search(r'(\d+)', cve_years)
                if match:
                    years_back = int(match.group(1))
                    return current_year - years_back + 1
            # 숫자 문자열
            try:
                return int(cve_years)
            except ValueError:
                pass
        
        return 1999  # 기본값

    async def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """Get specific CVE details"""
        params = {
            "cveId": cve_id
        }
        results = await self._make_request(params)
        return results[0] if results else None

    async def _make_request(self, params: Dict, silent_404: bool = False) -> List[Dict]:
        """Make request to NVD API with rate limiting and concurrency control
        
        Args:
            params: API 요청 파라미터
            silent_404: True면 404 에러 시 로그 출력 안 함 (날짜 범위 검색용)
        """
        # Acquire semaphore to limit concurrent requests
        async with self._semaphore:
            # Dynamic delay based on recent rate limit hits
            delay = self.rate_limit_delay
            if self._rate_limit_hits > 0:
                delay = self.rate_limit_delay * (self._rate_limit_hits + 1)

            await asyncio.sleep(delay)

            max_retries = 3
            for attempt in range(max_retries):
                try:
                    async with httpx.AsyncClient(timeout=30.0) as client:
                        response = await client.get(
                            self.BASE_URL,
                            params=params,
                            headers=self.headers
                        )
                        response.raise_for_status()
                        data = response.json()

                        # Success - reset rate limit counter
                        if self._rate_limit_hits > 0:
                            self._rate_limit_hits = max(0, self._rate_limit_hits - 1)

                        vulnerabilities = data.get("vulnerabilities", [])
                        return [self._parse_cve(vuln) for vuln in vulnerabilities]

                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 429:
                        self._rate_limit_hits += 1
                        wait_time = 30 * (attempt + 1)  # 30s, 60s, 90s
                        print(f"  Rate limit (시도 {attempt + 1}/{max_retries}), {wait_time}초 대기...")
                        await asyncio.sleep(wait_time)

                        if attempt == max_retries - 1:
                            print(f"  Rate limit 재시도 실패")
                            return []
                        continue
                    elif e.response.status_code == 404:
                        # 404는 해당 조건에 CVE가 없다는 의미 - 조용히 처리
                        # (날짜 범위에 데이터 없음, 키워드 매칭 없음 등)
                        return []
                    else:
                        print(f"HTTP error: {e}")
                        return []
                except httpx.HTTPError as e:
                    print(f"HTTP error: {e}")
                    return []
                except Exception as e:
                    print(f"Error: {e}")
                    return []

            return []

    def _parse_cve(self, vuln_data: Dict) -> Dict:
        """Parse CVE data from NVD response
        
        CVSS 우선순위: v4.0 > v3.1 > v3.0 > v2.0
        - cvss_score: 가장 높은 우선순위의 CVSS 점수 (UI 표시용)
        - cvss_version: 사용된 CVSS 버전 (예: "4.0", "3.1", "3.0", "2.0")
        - 개별 버전 점수도 별도 저장 (cvss_v4_score, cvss_v3_score, cvss_v2_score)
        """
        cve = vuln_data.get("cve", {})
        cve_id = cve.get("id", "")

        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            ""
        )

        published = cve.get("published")
        last_modified = cve.get("lastModified")

        metrics = cve.get("metrics", {})
        
        # === CVSS v4.0 (최우선) ===
        cvss_v4_score = None
        cvss_v4_severity = None
        cvss_v4_vector = None
        
        cvss_v4_list = metrics.get("cvssMetricV40", [])
        if cvss_v4_list:
            cvss_v4 = cvss_v4_list[0]
            cvss_v4_data = cvss_v4.get("cvssData", {})
            cvss_v4_score = cvss_v4_data.get("baseScore")
            cvss_v4_severity = cvss_v4_data.get("baseSeverity", "UNKNOWN")
            cvss_v4_vector = cvss_v4_data.get("vectorString")
        
        # === CVSS v3.1 ===
        cvss_v31_score = None
        cvss_v31_severity = None
        cvss_v31_vector = None
        cvss_v31_data = {}
        
        cvss_v31_list = metrics.get("cvssMetricV31", [])
        if cvss_v31_list:
            cvss_v31 = cvss_v31_list[0]
            cvss_v31_data = cvss_v31.get("cvssData", {})
            cvss_v31_score = cvss_v31_data.get("baseScore")
            cvss_v31_severity = cvss_v31_data.get("baseSeverity", "UNKNOWN")
            cvss_v31_vector = cvss_v31_data.get("vectorString")
        
        # === CVSS v3.0 ===
        cvss_v30_score = None
        cvss_v30_severity = None
        cvss_v30_vector = None
        cvss_v30_data = {}
        
        cvss_v30_list = metrics.get("cvssMetricV30", [])
        if cvss_v30_list:
            cvss_v30 = cvss_v30_list[0]
            cvss_v30_data = cvss_v30.get("cvssData", {})
            cvss_v30_score = cvss_v30_data.get("baseScore")
            cvss_v30_severity = cvss_v30_data.get("baseSeverity", "UNKNOWN")
            cvss_v30_vector = cvss_v30_data.get("vectorString")
        
        # === CVSS v2.0 ===
        cvss_v2_score = None
        cvss_v2_severity = None
        cvss_v2_vector = None
        cvss_v2_data = {}
        
        cvss_v2_list = metrics.get("cvssMetricV2", [])
        if cvss_v2_list:
            cvss_v2 = cvss_v2_list[0]
            cvss_v2_data = cvss_v2.get("cvssData", {})
            cvss_v2_score = cvss_v2_data.get("baseScore")
            cvss_v2_severity = cvss_v2.get("baseSeverity", "UNKNOWN")
            cvss_v2_vector = cvss_v2_data.get("vectorString")
        
        # === CVSS 우선순위 결정 (v4 > v3.1 > v3.0 > v2) ===
        # 기본 점수와 세부 정보를 결정
        cvss_score = None
        cvss_severity = None
        cvss_vector = None
        cvss_version = None
        cvss_details = {}  # attack_vector 등 세부 정보
        
        if cvss_v4_score is not None:
            cvss_score = cvss_v4_score
            cvss_severity = cvss_v4_severity
            cvss_vector = cvss_v4_vector
            cvss_version = "4.0"
            # v4는 다른 구조를 가짐 - 기본값 설정
            cvss_details = {
                "attackVector": "NETWORK",
                "attackComplexity": "LOW",
                "privilegesRequired": "NONE",
                "userInteraction": "NONE",
                "scope": "UNCHANGED",
                "confidentialityImpact": "NONE",
                "integrityImpact": "NONE",
                "availabilityImpact": "NONE"
            }
        elif cvss_v31_score is not None:
            cvss_score = cvss_v31_score
            cvss_severity = cvss_v31_severity
            cvss_vector = cvss_v31_vector
            cvss_version = "3.1"
            cvss_details = cvss_v31_data
        elif cvss_v30_score is not None:
            cvss_score = cvss_v30_score
            cvss_severity = cvss_v30_severity
            cvss_vector = cvss_v30_vector
            cvss_version = "3.0"
            cvss_details = cvss_v30_data
        elif cvss_v2_score is not None:
            cvss_score = cvss_v2_score
            cvss_severity = cvss_v2_severity
            cvss_vector = cvss_v2_vector
            cvss_version = "2.0"
            # v2 → v3 형식 변환 (세부 정보)
            cvss_details = {
                "attackVector": cvss_v2_data.get("accessVector", "UNKNOWN"),
                "attackComplexity": cvss_v2_data.get("accessComplexity", "UNKNOWN"),
                "privilegesRequired": "NONE",
                "userInteraction": "NONE",
                "scope": "UNCHANGED",
                "confidentialityImpact": cvss_v2_data.get("confidentialityImpact", "NONE"),
                "integrityImpact": cvss_v2_data.get("integrityImpact", "NONE"),
                "availabilityImpact": cvss_v2_data.get("availabilityImpact", "NONE")
            }

        # CVSS v3 통합 점수 (v3.1 우선, 없으면 v3.0)
        cvss_v3_score = cvss_v31_score if cvss_v31_score is not None else cvss_v30_score
        cvss_v3_severity = cvss_v31_severity if cvss_v31_severity is not None else cvss_v30_severity
        cvss_v3_vector = cvss_v31_vector if cvss_v31_vector is not None else cvss_v30_vector

        references = cve.get("references", [])
        ref_urls = [ref.get("url") for ref in references]

        configurations = cve.get("configurations", [])
        cpe_list = []
        version_ranges = []

        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        cpe_list.append(cpe_match.get("criteria", ""))
                        version_info = {
                            "criteria": cpe_match.get("criteria", ""),
                            "versionStartIncluding": cpe_match.get("versionStartIncluding"),
                            "versionEndIncluding": cpe_match.get("versionEndIncluding"),
                            "versionStartExcluding": cpe_match.get("versionStartExcluding"),
                            "versionEndExcluding": cpe_match.get("versionEndExcluding")
                        }
                        version_ranges.append(version_info)

        is_unauthorized = self._check_unauthorized_access(description, cvss_details)

        return {
            "cve_id": cve_id,
            "description": description,
            "published_date": self._parse_date(published),
            "last_modified": self._parse_date(last_modified),
            # === 통합 CVSS (우선순위 적용) ===
            "cvss_score": cvss_score,  # 최종 CVSS 점수 (v4 > v3.1 > v3.0 > v2)
            "cvss_severity": cvss_severity,
            "cvss_vector": cvss_vector,
            "cvss_version": cvss_version,  # 사용된 버전 ("4.0", "3.1", "3.0", "2.0")
            # === 버전별 CVSS (개별 저장) ===
            "cvss_v4_score": cvss_v4_score,
            "cvss_v4_severity": cvss_v4_severity,
            "cvss_v4_vector": cvss_v4_vector,
            "cvss_v3_score": cvss_v3_score,  # v3.1 또는 v3.0
            "cvss_v3_severity": cvss_v3_severity,
            "cvss_v3_vector": cvss_v3_vector,
            "cvss_v2_score": cvss_v2_score,
            "cvss_v2_severity": cvss_v2_severity,
            "cvss_v2_vector": cvss_v2_vector,
            # === 세부 정보 ===
            "attack_vector": cvss_details.get("attackVector"),
            "attack_complexity": cvss_details.get("attackComplexity"),
            "privileges_required": cvss_details.get("privilegesRequired"),
            "user_interaction": cvss_details.get("userInteraction"),
            "scope": cvss_details.get("scope"),
            "confidentiality_impact": cvss_details.get("confidentialityImpact"),
            "integrity_impact": cvss_details.get("integrityImpact"),
            "availability_impact": cvss_details.get("availabilityImpact"),
            "cpe_list": "|".join(cpe_list),
            "references": "|".join(ref_urls),
            "is_unauthorized_access": is_unauthorized,
            "version_ranges": version_ranges
        }
    
    def _extract_year_from_cve_id(self, cve_id: str) -> Optional[int]:
        """Extract year from CVE ID (e.g., CVE-2010-1234 -> 2010)"""
        try:
            parts = cve_id.split("-")
            if len(parts) >= 2:
                return int(parts[1])
        except:
            pass
        return None

    def _check_unauthorized_access(self, description: str, cvss_data: Dict) -> bool:
        """Check if CVE involves unauthorized access"""
        unauthorized_keywords = [
            "unauthorized access", "bypass authentication", "privilege escalation",
            "authentication bypass", "remote code execution", "arbitrary code",
            "elevate privileges", "gain access", "unauthenticated"
        ]

        description_lower = description.lower()
        has_keyword = any(keyword in description_lower for keyword in unauthorized_keywords)

        privileges_required = cvss_data.get("privilegesRequired", "").upper()
        has_no_privileges = privileges_required == "NONE"

        return has_keyword or has_no_privileges

    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO date string to datetime"""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except:
            return None

    async def download_year_data(self, year: int, progress_callback=None, force: bool = False) -> Dict:
        """
        특정 년도의 모든 CVE 데이터를 다운로드하여 캐시에 저장

        Args:
            year: 다운로드할 년도 (예: 2024)
            progress_callback: 진행상황 콜백 함수 (current, total, message)
            force: True이면 이미 다운로드된 데이터도 재다운로드

        Returns:
            Dict: 다운로드 통계 {"total": int, "cached": int, "year": int, "skipped": bool}
        """
        from datetime import datetime as dt

        # 현재 년도는 항상 재다운로드 (계속 업데이트되므로)
        current_year = dt.now().year
        is_current_year = (year == current_year)

        # 이미 다운로드된 년도인지 확인 (현재 년도 제외)
        if not force and not is_current_year:
            cache_key = f"__year_{year}__"
            existing_cves = self._get_cached(cache_key)
            if existing_cves:
                print(f"\n[NVD] {year} already downloaded ({len(existing_cves)} CVEs), skipping...", flush=True)
                return {
                    "year": year,
                    "total": len(existing_cves),
                    "cached_packages": 0,
                    "cache_key": cache_key,
                    "skipped": True
                }

        if is_current_year:
            print(f"\n[NVD] Downloading {year} CVE data (current year - always update)...", flush=True)
        else:
            print(f"\n[NVD] Downloading {year} CVE data...", flush=True)

        all_cves = []

        from datetime import datetime as dt, timedelta

        year_start = dt(year, 1, 1)
        year_end = dt(year, 12, 31, 23, 59, 59)

        current_start = year_start
        chunk_days = 119

        print(f"  Splitting year into 120-day chunks...", flush=True)

        while current_start <= year_end:
            current_end = min(current_start + timedelta(days=chunk_days), year_end)

            start_date_str = current_start.strftime("%Y-%m-%dT%H:%M:%S.000")
            end_date_str = current_end.strftime("%Y-%m-%dT%H:%M:%S.999")

            print(f"  Chunk: {current_start.strftime('%Y-%m-%d')} ~ {current_end.strftime('%Y-%m-%d')}", flush=True)

            chunk_cves = await self._download_date_range(start_date_str, end_date_str, progress_callback)
            all_cves.extend(chunk_cves)

            current_start = current_end + timedelta(seconds=1)

        print(f"  Total {len(all_cves)} CVEs downloaded", flush=True)

        print(f"  Caching year data... ({len(all_cves)} CVEs)", flush=True)
        cache_key = f"__year_{year}__"
        self._set_cached(cache_key, all_cves)
        print(f"  Year cache completed", flush=True)

        packages = set()
        for cve in all_cves:
            cpe_list = cve.get('cpe_list')
            if cpe_list:
                cpe_items = [cpe_list] if isinstance(cpe_list, str) else (cpe_list if isinstance(cpe_list, list) else [])
                for cpe in cpe_items:
                    parts = cpe.split(':')
                    if len(parts) >= 5 and parts[4] and parts[4] != '*':
                        packages.add(parts[4])
        
        package_count = len(packages)
        print(f"  Unique packages: {package_count}", flush=True)

        self._save_download_record(year, len(all_cves), package_count)

        if progress_callback:
            await progress_callback(len(all_cves), len(all_cves), f"Done! {len(all_cves)} CVEs downloaded")

        return {
            "year": year,
            "total": len(all_cves),
            "cached_packages": package_count,
            "cache_key": cache_key,
            "skipped": False
        }

    async def _download_date_range(self, start_date: str, end_date: str, progress_callback=None) -> List[Dict]:
        """날짜 범위의 CVE 다운로드 (120일 이하)"""
        all_cves = []
        start_index = 0
        results_per_page = 2000
        total_results = None

        while True:
            if progress_callback and total_results:
                await progress_callback(start_index, total_results, f"Downloading... ({start_index}/{total_results})")

            url = f"{self.BASE_URL}?pubStartDate={start_date}&pubEndDate={end_date}&resultsPerPage={results_per_page}&startIndex={start_index}"

            if start_index == 0:
                print(f"  [DEBUG] Full URL: {url}", flush=True)
                print(f"  [DEBUG] Headers: {self.headers}", flush=True)

            # API 호출 (rate limiting 포함 - 다운로드는 더 빠른 속도)
            async with self._semaphore:
                await asyncio.sleep(self.download_delay)

                try:
                    async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
                        response = await client.get(
                            url,
                            headers=self.headers
                        )

                        if start_index == 0:
                            print(f"  [DEBUG] Response status: {response.status_code}", flush=True)
                            if response.status_code == 404:
                                print(f"  [DEBUG] Response body: {response.text[:500]}", flush=True)
                        response.raise_for_status()
                        data = response.json()

                        if total_results is None:
                            total_results = data.get("totalResults", 0)
                            print(f"  Total {total_results} CVEs found", flush=True)

                        vulnerabilities = data.get("vulnerabilities", [])
                        parsed_cves = [self._parse_cve(vuln) for vuln in vulnerabilities]
                        all_cves.extend(parsed_cves)

                        print(f"  Progress: {len(all_cves)}/{total_results} CVEs downloaded", flush=True)

                        # 다음 페이지 확인
                        if len(all_cves) >= total_results:
                            break

                        start_index += results_per_page

                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 429:
                        print(f"  Rate limit reached, waiting 60 seconds...", flush=True)
                        await asyncio.sleep(60)
                        continue
                    elif e.response.status_code == 404:
                        print(f"  No data for this date range (404) - Normal for future dates", flush=True)
                        break
                    else:
                        print(f"  HTTP error: {e}", flush=True)
                        break
                except Exception as e:
                    print(f"  Error: {e}", flush=True)
                    break

        return all_cves

    async def download_year_range(self, start_year: int, end_year: int = 2026, progress_callback=None, force: bool = False) -> Dict:
        """
        년도 범위의 CVE 데이터를 순차적으로 다운로드

        Args:
            start_year: 시작 년도
            end_year: 종료 년도 (기본값: 2026)
            progress_callback: 진행상황 콜백
            force: True이면 이미 다운로드된 데이터도 재다운로드

        Returns:
            Dict: 전체 다운로드 통계
        """
        total_cves = 0
        total_packages = 0
        downloaded_years = []
        skipped_years = []

        for year in range(start_year, end_year + 1):
            try:
                print(f"\n[Range Download] Processing {year}... ({year - start_year + 1}/{end_year - start_year + 1})", flush=True)

                result = await self.download_year_data(year, progress_callback, force=force)

                total_cves += result['total']
                total_packages += result.get('cached_packages', 0)
                if result.get('skipped'):
                    skipped_years.append(year)
                else:
                    downloaded_years.append(year)

            except Exception as e:
                print(f"[Error] Failed to download {year}: {e}", flush=True)
                continue

        return {
            "start_year": start_year,
            "end_year": end_year,
            "total_cves": total_cves,
            "total_packages": total_packages,
            "downloaded_years": downloaded_years,
            "skipped_years": skipped_years
        }

    def _save_download_record(self, year: int, cve_count: int, package_count: int):
        """다운로드 기록 저장"""
        conn = sqlite3.connect(self._cache_db_path)

        # 다운로드 기록 테이블 생성
        conn.execute("""
            CREATE TABLE IF NOT EXISTS download_records (
                year INTEGER PRIMARY KEY,
                cve_count INTEGER,
                package_count INTEGER,
                downloaded_at REAL,
                size_bytes INTEGER
            )
        """)

        # 캐시 크기 계산
        cache_key = f"__year_{year}__"
        cursor = conn.execute(
            "SELECT LENGTH(cves) FROM nvd_cache WHERE keyword = ?",
            (cache_key,)
        )
        row = cursor.fetchone()
        size_bytes = row[0] if row else 0

        # 기록 저장
        conn.execute("""
            INSERT OR REPLACE INTO download_records
            (year, cve_count, package_count, downloaded_at, size_bytes)
            VALUES (?, ?, ?, ?, ?)
        """, (year, cve_count, package_count, time.time(), size_bytes))

        conn.commit()
        conn.close()

    def get_download_records(self) -> List[Dict]:
        """다운로드 기록 조회 (실제 캐시 데이터 존재 여부도 검증)"""
        conn = sqlite3.connect(self._cache_db_path)

        # 테이블이 없으면 생성
        conn.execute("""
            CREATE TABLE IF NOT EXISTS download_records (
                year INTEGER PRIMARY KEY,
                cve_count INTEGER,
                package_count INTEGER,
                downloaded_at REAL,
                size_bytes INTEGER
            )
        """)

        cursor = conn.execute("""
            SELECT year, cve_count, package_count, downloaded_at, size_bytes
            FROM download_records
            ORDER BY year DESC
        """)

        records = []
        orphaned_years = []
        for row in cursor.fetchall():
            year, cve_count, pkg_count, downloaded_at, size_bytes = row
            
            # 실제 캐시 데이터 존재 여부 확인
            cache_key = f"__year_{year}__"
            cache_check = conn.execute(
                "SELECT 1 FROM nvd_cache WHERE keyword = ? LIMIT 1",
                (cache_key,)
            ).fetchone()
            
            if cache_check is None:
                # 기록은 있지만 실제 데이터가 없는 경우 (고아 레코드)
                orphaned_years.append(year)
                continue
            
            records.append({
                "year": year,
                "cve_count": cve_count,
                "package_count": pkg_count,
                "downloaded_at": datetime.fromtimestamp(downloaded_at).isoformat(),
                "size_bytes": size_bytes,
                "size_mb": round(size_bytes / (1024 * 1024), 2) if size_bytes else 0
            })

        # 고아 레코드 정리 (실제 데이터가 없는 다운로드 기록 삭제)
        if orphaned_years:
            print(f"[정리] 실제 데이터가 없는 다운로드 기록 {len(orphaned_years)}개 정리: {sorted(orphaned_years)}")
            for year in orphaned_years:
                conn.execute("DELETE FROM download_records WHERE year = ?", (year,))
            conn.commit()

        conn.close()
        return records

    def delete_year_data(self, year: int) -> bool:
        """특정 년도 데이터 삭제"""
        conn = sqlite3.connect(self._cache_db_path)

        try:
            # 캐시 삭제
            cache_key = f"__year_{year}__"
            conn.execute("DELETE FROM nvd_cache WHERE keyword = ?", (cache_key,))

            # 다운로드 기록 삭제
            conn.execute("DELETE FROM download_records WHERE year = ?", (year,))

            conn.commit()
            print(f"[삭제 완료] {year}년 데이터 삭제됨")
            return True

        except Exception as e:
            print(f"[삭제 실패] {year}년: {e}")
            return False
        finally:
            conn.close()
