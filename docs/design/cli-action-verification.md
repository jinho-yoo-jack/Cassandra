# CLI/Action 리팩토링 초기 검증 기록

## 범위와 기준

이 기록은 그래프 UX 개선과 별도 Action 저장소 분리 이전의 로컬 리팩토링 snapshot에 대한 증거 요약이다. 이후 작업 트리 전체의 최신 검증 결과로 읽으면 안 된다. 당시 GitHub 원격 CI 실행, Marketplace 게시, merge 또는 릴리스 발행은 하지 않았다. 후속 게시 절차는 [릴리스 계획](../releases/v0.1.0-plan.md)과 실제 원격 실행 결과로 구분한다.

- 기준/최종 Git HEAD: `0340e3b2046873698ac39722885193a2dde6675a` (`main`, 미커밋 작업 트리).
- 최종 코드·빌드 입력 fingerprint: `8ac777b142dd4ece4269155bef329cbf770b747d6e8cd3f95df0b54a541c6e49`.
- 환경: Go 1.27.3 darwin/arm64, Node 26.7.0; Linux 실행은 Docker linux/arm64.
- 실제 파일·도구 출력에 근거한다. 별도의 불변 CI receipt나 원격 실행 증거는 생성하지 않았다.

## 요구사항 → 작업 → 증거

원래 승인 문서에는 ID가 없어 이 검증 단계에서 문서 순서에 따라 부여했다. 작업 대응은 내용 기반 매핑이며, 이 표 자체가 테스트 성공 증거를 대신하지 않는다.

| 요구사항 | 작업 ID | 관측한 검증/회귀 경로 |
|---|---|---|
| FR-001: 기존 추출기·그래프·취약점 매칭을 웹/CLI가 공유 | core | TestDirectoryAndGitScanParity; pkg/apiserver TestEndToEnd |
| FR-002: CycloneDX 1.6 / SPDX 2.3 보존 | cli, verify | TestExistingReportFormats; 최종 Linux 산출물의 공식 CycloneDX/SPDX 스키마 검증 |
| FR-003: 웹 API·SSE 및 report 저장 형식 보존 | core, app | TestReportStorageCompatibility; TestEndToEnd; Node watch-cache/use-watch 특성 테스트 |
| FR-004: 웹 승인·조치·draft PR·배포 차단 보존 | app | controller/remediation controller_test.go, executor_test.go, workflow_test.go; TestEndToEnd |
| FR-005: 서버 없는 읽기 중심 CLI 및 검사 전용 Action | cli, action | TestScanValidatesBeforeNetworkAndNeverExecutesTargetScripts; TestPackagedCLIEntryPoint; scripts/test_action.py |
| FR-006: 불완전 검사와 취약점 임계값 실패 구분 | core, cli | TestIncompleteDeclarationsCannotPassCLI; TestParserDiagnosticsReachCIPolicy; provider HTTP/pagination 테스트; scripts/smoke_scan.py |
| FR-007: 웹의 재평가 유지·Action은 실행 시점 검사 | core, action | TestEndToEnd 웹훅/재평가; CLI에 controller/feed 루프 없음; 예약 workflow 사용 예시 |
| FR-008: 프런트 책임 분리와 기존 동작 보존 | app | npm test: 72 passed; npm run typecheck; npm run build; 1280/768px 로컬 브라우저 스모크 |
| SC-001: 고정 release 다운로드·체크섬·실패 시 결과 보존 | action | scripts/test_action.py: 5 passed; actionlint; Action 공식 메타데이터 스키마 |
| SC-002: 전체 회귀와 실제 배포용 실행 파일 검증 | verify | make test; go test -race -count=1 -timeout 5m ./...; archive checksum; scripts/smoke_scan.py; 최종 Linux 실제 API 스캔 |
| SC-003: 승인된 범위·기존 변경 보존·원격 무변경 | audit, approval, verify | 사용자 전체 진행 승인; 기준/최종 HEAD 동일; 기존 FixTarget/hover 동작 테스트 및 화면; commit/tag/push/release 실행 없음 |

## 실행 결과

모든 결과는 위 코드 fingerprint의 현재 checkout 또는 그 checkout에서 빌드한 산출물을 대상으로 한다. 소스가 바뀌면 다시 검증해야 한다.

| 명령/검증 | 실행 위치/대상 | 결과·범위 |
|---|---|---|
| `make test` | 저장소 루트 | exit 0. Go vet/race 전체, Node 72개, TypeScript, Action 계약 5개 |
| `go test -race -count=1 -timeout 5m ./...` | `backend/` | exit 0. 캐시 없이 전체 Go 테스트; 기존 apiserver E2E 포함 |
| `npm run build` | `web/` | exit 0. TypeScript 및 Vite 배포 빌드 |
| `make backend` | 저장소 루트 | exit 0. API 서버 및 CLI 실행 파일 생성 |
| `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 -shellcheck= .github/workflows/ci.yml .github/workflows/release.yml` | 저장소 루트 | exit 0. workflow 문법/표현식 검사; ShellCheck 실행을 뜻하지 않음 |
| `bash -n scripts/action.sh scripts/release.sh` | 저장소 루트 | exit 0. 셸 문법 |
| JSON Schema 검증 | `action.yml` → JSON, SchemaStore github-action | 오류 없음. Go YAML converter와 jsonschema 사용 |
| `make release VERSION=v0.1.0` | 저장소 루트 | exit 0. Linux/macOS × amd64/arm64 archive와 checksums.txt 생성; 게시 없음 |
| `shasum -a 256 --check checksums.txt` | `dist/` | 생성한 archive 모두 OK |
| `python3 scripts/smoke_scan.py <압축 해제한 darwin/arm64 CLI>` | 로컬 fixture HTTP 서버 | 테스트 명령 exit 0; 실제 실행 파일에서 정책 차단=1, gate 해제=0, 불완전 입력=2 |
| `<압축 해제한 linux/arm64 CLI> scan --path /source --output-dir /results --timeout 90s --fail-on high` | 읽기 전용 Docker 컨테이너, requests==2.19.1 fixture | 실제 공개 API 조회. 컴포넌트 1개·취약점 5건, 기대한 exit 1; 소스 mount 읽기 전용 |
| 공식 JSON Schema + format 검사 | 최종 Linux 실행의 SARIF/CycloneDX/SPDX 파일 | 세 형식 모두 오류 없음 |
| `git diff --check` | 저장소 루트 | exit 0 |

## 독립 리뷰와 수정 검증

독립 리뷰는 처음에 배포 불가 의견이었다. 지적을 숨기지 않고 직접 재현한 뒤 아래 수정과 회귀 검증을 적용했다. 최종 수정 결과는 부모 실행자가 같은 재현 경로와 전체 테스트로 확인했으며, 이를 별도의 원격 승인이나 새 독립 리뷰 verdict로 표현하지 않는다.

| 재현된 문제 | 수정 | 수정 후 관측 |
|---|---|---|
| 출력 디렉터리 링크를 따라 외부 report.json 덮어쓰기 | 경로 구성요소별 실제 디렉터리 확인, 열린 inode 비교, os.Root handle 기반 임시 파일·Rename | exit 2, 외부 sentinel 보존. 직접·중간 디렉터리 링크와 최종 파일 링크 테스트 |
| 링크 manifest를 조용히 생략 | 지원 manifest 생략 진단 | exit 2, report에 inventory 경고 |
| 미고정/잘못된 requirements 및 빈 lockfile을 정상 처리 | Result.Warnings, Python/JS/Go 해석 진단, companion 파일 접근 실패 전달 | 재현 입력 exit 2; 실제 빈 프로젝트는 exit 0 유지 |
| 불완전 NVD 페이지를 완료로 간주 | 필수 구조, 시작점/개수/전체 개수, CVE ID 검증 | 잘못된 페이지는 경고/exit 2. NVD E2E fixture도 실제 메타데이터를 갖추도록 수정; 기존 assertions 유지 |
| EPSS 자체 HTTP timeout을 부모 취소로 오인 | ctx.Err()로 실제 호출자 취소 구분 | Match는 finding+경고, 캐시 CVE REST는 성공. 실제 부모 취소는 계속 전파 |

KEV/EPSS의 malformed 응답도 테스트하며 실패 시 기존 카탈로그/캐시를 보존한다. 모든 생태계·lock dialect의 의미적 정합성을 완전 검증한다는 보장은 아니다. 미지원 해석 기능은 새 resolver를 추측 구현하지 않고 경고로 남긴다.

## 화면 스모크 확인

현재 배포 번들을 임시 로컬 API 서버로 제공하고, 위 실제 CLI 보고서를 **로컬 테스트용** scan 데이터로 넣어 확인했다. 사용자 데이터베이스는 사용하지 않았다.

- 1280×900: 홈 → 그래프 이동, 노드/연결 표시, 취약점 hover와 기존 FixTarget 2.33.0 표시.
- 768×900: 검색·전체 보기, Fit View 실제 클릭, 조치 빈 목록, 수평 overflow 없음.
- 관측 구간의 error/unhandledrejection 배열과 실패 resource 목록은 비어 있었다. 정상 API/SSE 요청은 서버 로그에서 200으로 확인했다.
- 캡처는 작업 당시 로컬 scratch의 captures.json 및 PNG로 보존했고 저장소에는 포함하지 않았다. 확인 후 테스트 서버를 종료했다.
- 브라우저 source fingerprint: `42d7721b414a13900564ec1aade83e0e0157e49fe70bdaf60533afd04748ac9e`. 이후 프런트 소스는 바뀌지 않았고 최종 빌드도 같은 asset 이름을 생성했다.
- 이 확인은 전 화면·모바일·접근성·실제 네트워크 재연결·장시간 동작의 전수 검증이나 pixel-diff 판정이 아니다.

## 남은 외부 단계와 한계

- 이 초기 검증 이후에는 대응 Action 커밋과 release assets 게시 및 소비자 저장소의 실제 workflow 실행이 필요하다. Action wrapper와 그 테스트는 후속 배포에서 별도 `cassandra-action` 저장소로 이동한다.
- GitHub-hosted 환경의 실패 후 composite outputs 전달, artifact 업로드, 저장소별 SARIF 권한은 원격 실행 전까지 미검증이다.
- Linux/macOS의 양쪽 아키텍처를 빌드했지만 실제 실행은 이 호스트의 darwin/arm64 및 Docker linux/arm64에서 관측했다. amd64는 빌드/체크섬 검증에 한정한다.
- Node 모듈 mocking은 실험 기능 경고를 내지만 테스트 실패는 없었다.
- 기존 범위 밖 기능(인증, 이미지 OS 패키지, PR 기준선 차이 검사, 외부 PR exactly-once)은 추가하지 않았다.

## Coverage pass 결과

중복·모호성·미정의·원칙 충돌·누락·용어 불일치 순으로 검토했다. 배포 전제와 실제 검증 범위를 명시했으며, 승인된 로컬 구현 범위에 대한 미해결 차단 항목은 없다. 아래 비율은 **요구사항-작업 매핑** 비율이지 보안 탐지율이나 테스트 완전성 수치가 아니다.

```json
{
  "functional_requirements": 8,
  "success_criteria": 3,
  "tasks_mapped": 7,
  "unmapped_tasks": [],
  "requirements_with_zero_tasks": 0,
  "requirements_without_evidence": 0,
  "mapping_coverage_percent": 100.0
}
```
