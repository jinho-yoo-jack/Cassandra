# 공통 분석 엔진, CLI/Action 및 책임 경계 리팩토링

상태: 이 초기 리팩토링 단계의 로컬 구현·검증 완료. 당시 commit/tag/push/원격 CI/릴리스 발행은 범위 밖이었다. 후속 승인으로 그래프 UX 개선과 별도 Action 저장소 배포가 추가됐으며 [릴리스 계획](../releases/v0.1.0-plan.md)에서 추적한다. 초기 실행 결과와 검증 한계는 [검증 기록](cli-action-verification.md)에 정리했다. 아래 계획은 실행 증거와 구분한다.

## 목표와 기준선

목표는 별도 서버 없이 Cassandra를 CI에서 사용하면서 웹과 CLI의 분석 결과가 갈라지지 않게 하고, 외부 시스템/출력/화면 변경을 독립적으로 테스트하는 것이다. 기존 웹 서비스의 스캔, 그래프, 지속 재평가, 승인 후 조치 기능은 유지한다.

- 기준 revision: `0340e3b2046873698ac39722885193a2dde6675a` + 작업 시작 당시의 미커밋 변경.
- 기존 변경: API GraphNode.fixTarget, codegraph 취약 경로, report.FixTarget, remediation scenarios/steps 및 scenarios_test.go, graph 필드, 프런트엔드 fixTarget와 hover 표시. 삭제하거나 되돌리지 않는다.
- 관측한 기준선: `/opt/homebrew/bin/go`는 Go 1.27.3. `PATH=/opt/homebrew/bin:$PATH`에서 `make test` 성공(Go vet/race 전체 테스트 + 프런트 타입 검사). 기본 PATH의 Go 1.18.3은 사용하지 않는다.
- 원본 자료: scanner/scanner.go, inventory/extractor.go, vulndb/matcher.go, report/report.go, apiserver/apiserver.go, controller/remediation 및 registry의 실제 소스/호출자, web/src/lib/api.ts, hooks/use-watch.ts, components/graph.

## 보존 및 변경 계약

| 원본 기능 | 처리 | 결과 계약/검증 |
|---|---|---|
| 모든 기존 inventory extractor, codegraph, OSV/NVD 매칭, KEV/EPSS | 재사용 | 같은 fixture의 Git 스캔과 디렉터리 스캔에서 inventory/code/findings 비교 |
| CycloneDX 1.6 / SPDX 2.3 | 재사용 | 기존 encoder 출력 사용; JSON 구조와 컴포넌트/취약점 보존 테스트 |
| 웹 REST/SSE, 저장된 보고서 JSON | 보존 | 기존 apiserver E2E + 저장소 round-trip |
| 웹 자동 수정/검토/승인/PR/배포 | 보존 | 기존 E2E + fake executor 상태 전이 테스트 |
| Action에서 자동 수정/PR/배포 | 제외(앞선 제안의 검사 전용 범위) | Action에는 쓰기 권한/실행 진입점 없음 |
| CLI의 clone/API 서버/Bolt DB/Docker 필요성 | 제거 | checkout 디렉터리를 직접 분석; 외부 도구 실행 없이 fixture 검사 |
| 오류를 숨기는 부분 검사 | 명시적 정책 | CLI는 파싱/필수 조회 실패와 임계값 초과를 구별, 불완전 검사 정상 통과 금지 |
| 실시간 새 취약점 감시 | 웹에서 유지 | Action은 실행 시점 검사; 예약 실행 예시 제공 |
| 기존 UI의 시각 디자인/쿼리 키/승인 동작 | 보존 | Node 특성 테스트 + 타입 검사/빌드, 가능한 로컬 브라우저 확인 |

비목표: 모든 타입에 인터페이스 부여, 범용 플러그인 프레임워크, 클래스 계층, 저장 스키마 마이그레이션, 인증/멀티테넌시, 이미지 OS 패키지 검사, PR 차이 기준선 판정, 배포/원격 릴리스 발행. 외부 PR의 exactly-once 생성 문제는 이번 구조 변경만으로 해결됐다고 주장하지 않는다.

## 책임 경계와 패턴

- SRP: 소스 획득, 분석, 정책 판정, 출력, 영속 저장, HTTP 전달, UI 계산 분리.
- DIP/ISP: 소비자가 실제 호출하는 메서드만 인터페이스로 선언. 이미 있는 extractor와 runner 전략은 재사용.
- Adapter: Git checkout/로컬 디렉터리, 메모리/영속 캐시, HTTP 어댑터.
- Strategy: 보고서 출력 형식과 기존 생태계별 extractor. 형식 추가 시 CLI 제어 흐름에 포맷별 코드를 누적하지 않는다.
- Command: remediation 단계 실행 registry. queue/retry/status와 외부 실행 의존성을 분리하고 승인 단계는 controller의 상태 전이로 유지.
- Composition root: scan 전용 생성 경로를 웹/CLI가 공유. CLI에 서버 옵션과 Docker 검증을 재사용하지 않는다.
- 작은 인터페이스의 대체 구현으로 동일 계약 테스트를 통과시켜 LSP를 확인한다. 추상화 자체를 목표로 삼지 않는다.

## 단계와 검증/롤백

각 단계는 계약과 실패 테스트 → 구현/어댑터 → 호출자 전환 → 전체 회귀 확인 → 사용하지 않는 기존 코드 정리 순으로 진행한다. 테스트는 기능별 RED/GREEN으로 작성한다. 호환성 특성 테스트는 변경 전 통과 결과를 기준으로 삼는다.

| 단계 | 단일 결과 | 외부 판정자/검증 | 롤백 경계 |
|---|---|---|---|
| A | 공통 분석·조회·저장 계약과 로컬 분석 구현 | Go unit/race 테스트, 기존 웹 E2E, Git/디렉터리 결과 비교 | 기존 생성/호출 경로 유지 중 신규 경로만 제거 가능 |
| B | headless CLI, JSON/Markdown/SBOM/SARIF 출력과 종료 코드 | 빌드한 실행 파일을 fixture HTTP 서버와 실제 디렉터리로 실행; 정상/취약/부분 실패/timeout 검증 | 새 CLI 및 출력 경로만 철회, 웹 그대로 |
| C | Composite Action 및 버전 고정 바이너리 패키징 | Action 스크립트 계약 테스트, YAML 검증, 릴리스 archive를 풀어 CLI 실행 | 신규 Action/workflow만 철회 |
| D | 조치 executor 분리 및 프런트 책임 분리 | 기존 E2E, fake executor 상태 전이, Node 실제 QueryClient 테스트, tsc/Vite build | 각 호출자 그룹별 원상 복구 가능 |
| E | 문서·사용 예시·전체 회귀 | make test, web build, CLI smoke, diff --check, 독립 리뷰 | 자기 변경만 역패치; 기존 사용자 변경 보존 |

사용자 요청 없이 commit/tag/stash/reset/checkout/push하지 않는다. 롤백은 작업 시작 상태를 보존하며 자기 변경만 되돌리는 검토된 역패치로 한다. 원격 Actions 실행과 release 게시 증거는 로컬 검사와 별도로 기록한다.

## 승인 시 파일 계획과 적용 차이

아래는 승인 시 파일 계획을 실제 분리 방식에 맞춰 보정한 표다. 경로는 저장소 루트 기준이다. 추가 회귀 테스트와 리뷰 수정은 표 아래에 별도로 기록한다. A/B/C/D는 소유 경로가 겹치지 않는 작업만 병렬화했다.

| 파일 | 작업 | 단계 | 의존 |
|---|---|---|---|
| backend/pkg/scanner/scanner.go | 수정: clone 어댑터로 축소 | A | engine |
| backend/pkg/scanner/engine.go | 생성: fs 기반 분석/작은 matcher 계약 | A | inventory/report |
| backend/pkg/scanner/scanner_test.go | 생성: 로컬/Git 결과·취소·오류 비교 | A | engine |
| backend/pkg/inventory/extractor.go | 수정: 추출 진단의 명시적 전달 | A | 기존 extractor 계약 |
| backend/pkg/inventory/extractor_test.go | 생성: 파싱/읽기/취소 실패 | A | 진단 계약 |
| backend/pkg/report/report.go | 수정: 영속 구현 분리, FixTarget 보존 | A | 없음 |
| backend/pkg/report/store.go | 생성: 작은 저장소 계약 | A | Report |
| backend/pkg/reportstore/store.go | 생성: 기존 Bolt 어댑터 | A | report/boltstore |
| backend/pkg/reportstore/store_test.go | 생성: round-trip | A | 어댑터 |
| backend/pkg/controller/scan/controller.go | 수정: 소비자 인터페이스 | A | engine/report |
| backend/pkg/registry/scan/storage.go | 수정: report reader/store 계약 | A | report |
| backend/pkg/registry/remediation/storage.go | 수정: report reader 계약 | A | report |
| backend/pkg/vulndb/matcher.go | 수정: provider/cache 계약과 오류 전달 | A | contracts |
| backend/pkg/vulndb/contracts.go | 생성: 필요한 provider/cache 인터페이스 | A | 기존 client 타입 |
| backend/pkg/vulndb/cache.go | 기존 Bolt 어댑터 재사용, 구현 변경 없음 | A | contracts |
| backend/pkg/vulndb/memory_cache.go | 생성: 메모리 캐시 | A | contracts |
| backend/pkg/vulndb/lookup.go | 생성: advisory 조회 서비스 | A | contracts |
| backend/pkg/vulndb/lookup_test.go | 생성: fallback/실패/캐시 계약 | A | lookup |
| backend/pkg/vulndb/matcher_test.go | 수정: 기존 매칭 보존/조회 실패 검증 | A | matcher |
| backend/pkg/registry/vulnerability/storage.go | 수정: 조회 서비스에 위임 | A | lookup |
| backend/pkg/bootstrap/scan.go | 생성: scan 전용 composition root | A | providers/extractors |
| backend/pkg/bootstrap/scan_test.go | 생성: 생성 시 무통신/초기화 계약 | A | bootstrap |
| backend/cmd/cassandra-apiserver/app/server.go | 수정: 공통 scan 구성 재사용 | A | bootstrap |
| backend/pkg/apiserver/apiserver.go | 수정: 어댑터 조립 | A | reportstore/bootstrap |
| backend/pkg/apiserver/apiserver_test.go | 수정: 동등성/기존 E2E 보존 | A | 서버 |
| backend/cmd/cassandra/main.go | 생성: CLI 프로세스 진입점 | B | CLI app |
| backend/cmd/cassandra/app/command.go | 생성: 옵션/검사/산출물/종료 코드 | B | engine/output/policy |
| backend/cmd/cassandra/app/command_test.go | 생성: end-to-end CLI 계약 | B | CLI |
| backend/pkg/scanpolicy/policy.go | 생성: 심각도/불완전 검사 정책 | B | report |
| backend/pkg/scanpolicy/policy_test.go | 생성: 정책 경계 | B | policy |
| backend/pkg/output/output.go | 생성: encoder registry | B | report/sbom |
| backend/pkg/output/sarif.go | 생성: SARIF adapter | B | report |
| backend/pkg/output/markdown.go | 생성: 안전한 요약 | B | report |
| backend/pkg/output/output_test.go | 생성: 각 형식 계약 | B | encoders |
| action.yml | 생성: 얇은 Composite Action | C | 릴리스/CLI |
| scripts/action.sh | 생성: 다운로드/검증/실행 | C | CLI 계약 |
| scripts/test_action.py | 생성: 잘못된 입력/체크섬/종료 코드 검증 | C | action script |
| scripts/smoke_scan.py | 생성: 패키징된 CLI의 실제 0/1/2 경로 검사 | C | release archive |
| scripts/release.sh | 생성: 바이너리 archive/checksum | C | Go build |
| .github/workflows/ci.yml | 생성: 테스트/Action smoke | C | A/B/C/D |
| .github/workflows/release.yml | 생성: 태그 기반 패키징 | C | release script |
| backend/pkg/controller/remediation/controller.go | 수정: 상태/queue에 집중 | D | executor |
| backend/pkg/controller/remediation/executor.go | 생성: 단계 Command registry | D | 기존 단계 |
| backend/pkg/controller/remediation/ports.go | 생성: 실제 실행 의존성 계약 | D | 실제 소비 메서드 |
| backend/pkg/controller/remediation/controller_test.go | 생성: 전이/취소/실패 | D | executor |
| backend/pkg/controller/remediation/steps.go | 수정: 실행 receiver 분리 | D | executor |
| backend/pkg/controller/remediation/scenarios.go | 수정: 실행 receiver 분리 | D | executor |
| backend/pkg/controller/remediation/docs.go | 기존 독립 함수 재사용, 변경 불필요 | D | executor |
| web/src/lib/api-types.ts | 생성: 기존 타입 이동 | D | 없음 |
| web/src/lib/http.ts | 생성: 전송 책임 | D | api-types |
| web/src/lib/api.ts | 수정: 기존 facade/재수출 유지 | D | http/types |
| web/src/lib/watch-cache.ts | 생성: 캐시 갱신 정책 | D | QueryClient |
| web/src/hooks/use-watch.ts | 수정: SSE 수명 관리 | D | watch-cache |
| web/src/components/graph/graph-model.ts | 생성: 순수 표시 계산 | D | API 타입 |
| web/src/components/graph/scan-graph.tsx | 수정: 순수 계산 위임 | D | graph-model |
| web/src/components/graph/graph-node.tsx | 수정: 타입 소유권 | D | graph-model |
| web/tests/register-ts.mjs | 생성: native Node 테스트 import 지원 | D | 설치된 Node |
| web/tests/api.test.mjs | 생성: 전송 특성 테스트 | D | api/http |
| web/tests/watch-cache.test.mjs | 생성: 캐시 정책 특성 테스트 | D | QueryClient |
| web/tests/graph-model.test.mjs | 생성: 그래프 특성 테스트 | D | graph-model |
| web/package.json | 수정: native test 명령 | D | tests |
| Makefile | 수정: CLI/test/release 대상 | E | B/C/D |
| README.md | 수정: CLI/Action/제약 | E | 실행된 계약 |
| README.ko.md | 수정: 동일 내용 | E | 실행된 계약 |
| docs/design/architecture.md | 수정: 실제 책임 경계 | E | 구현 결과 |
| docs/design/cli-action-refactor.md | 갱신: 결정·진행·검증 | E | 증거 |

## Review Focus

구현 중 확인한 경계에 따라 `cmd/cassandra/app/artifacts.go`로 안전한 출력 책임을 추가 분리했다. `inventory.Result.Warnings`, Python/JavaScript/Go 파서 진단, OSV/NVD/KEV/EPSS 응답 검증과 해당 회귀 테스트를 추가했다. 조치의 executor/workflow 테스트, 프런트 `use-watch.test.mjs`·`watch-harness.mjs`, CLI `artifacts_test.go`·`regression_test.go`도 초기 표보다 구체화됐다. 기존 E2E assertions는 유지하고 NVD fixture의 페이지 메타데이터만 실제 응답 계약에 맞췄다.

1. 불완전 검사가 정상 통과하는 경로: advisory 상세 실패, NVD 실패, KEV 초기화 실패, malformed manifest, unreadable root를 A/B에서 테스트. 정상·취약·검사오류를 분리한다.
2. 로컬 스캔이 PR 코드/스크립트를 실행하거나 디렉터리를 삭제하는 위험: A/B에서 checkout 보존 및 clone/execution 미호출 테스트. 신뢰하지 않는 입력은 shell 문자열에 직접 삽입하지 않는다.
3. 메모리 캐시 alias/병렬 접근/Enrich 변이: A에서 race 및 반환 객체 격리 테스트.
4. 조치의 승인 전 push, 테스트 실패 후 배포, 취소 중 완료 처리: D의 상태 테스트와 기존 apiserver E2E로 차단 계약 보존.
5. Action의 조작된 version/path/checksum와 실패 시 산출물 유실: C의 스크립트 테스트. GitHub-hosted 실행이 없으면 로컬 동작만 검증됐다고 명시.

프런트 watch의 오래된 이벤트가 목록에 반영되는 현상과 callback 변경 시 재구독은 기존 동작이다. 이번 책임 추출에서 몰래 정책 변경하지 않으며, 별도 재현 테스트를 근거로 후속 수정 범위를 결정한다.
