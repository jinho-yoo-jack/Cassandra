# Cassandra 설계 기록

사용법과 구조 개요는 [README](../../README.md), 피드 조사는 [vulnerability-feeds.md](../research/vulnerability-feeds.md)에 있습니다. 이 문서는 README에 없는 **설계 결정과 그 이유**만 기록합니다.

## 핵심 결정

| 결정 | 이유 |
|---|---|
| SBOM(인벤토리)이 스캔 결과의 원본이고, 그래프·CycloneDX·SPDX는 그 뷰 | 하나의 원본에서 파생하므로 그래프와 SBOM이 어긋나지 않음 |
| 버전 범위 판정은 OSV·NVD 서버에 맡김 (`querybatch`, `cpeName`+`isVulnerable`) | 생태계별 버전 규칙(PEP 440, Maven 등)을 직접 구현하면 오판 위험. 로컬 버전 비교는 "가장 가까운 수정 버전" 선택에만 사용 |
| 피드 변경 시 저장된 스캔 전체가 아니라 **해당 패키지를 가진 스캔만** 재평가 | 패키지 키 → 스캔 인덱스(scan controller). 재평가는 clone 없이 저장된 인벤토리로 재매칭 |
| 리소스는 bbolt 위의 제네릭 `Store[T]` + watch | etcd 없이 kube-apiserver의 list+watch, `GuaranteedUpdate`, resourceVersion 의미를 그대로 사용. UI는 SSE watch로 폴링 없이 갱신 |
| 컨트롤러는 client-go workqueue + 단계별 재시도 | 서버가 재시작되면 Running 단계를 Pending으로 되돌려 다시 실행. 작업 사본 기반 단계는 reset 후 재실행하되, 외부 PR 생성과 상태 저장 사이의 장애까지 exactly-once로 보장하지는 않음 |
| 테스트 실패는 파이프라인을 멈추지 않고 검토로 넘김 | 실패 원인이 프로젝트 자체 문제일 수 있음(예: `npm test`가 `snyk test`). 사람이 판단하고, 승인해도 Draft PR만 만들며 배포하지 않음 |
| 수정 커밋을 **테스트 실행 전에** 먼저 함 | 테스트가 만든 `node_modules`, `target/` 같은 산출물이 커밋에 섞이지 않도록 |
| 비고정 이미지 태그(`latest`, `5`, `1.25`)는 버전 판정을 하지 않음 | 실데이터에서 `mysql:5`를 버전 "5"로 매칭하자 오탐 168건이 나왔음. 대신 "미고정"으로 표시 |
| CVSS v2만 있는 오래된 CVE는 NVD의 v2 등급을 사용 | 실데이터에서 2014–2016년 CVE 89건이 심각도 UNKNOWN으로 나왔음 |
| 정확히 고정된 npm 버전(`"1.9.0"`)은 수정 후에도 정확한 고정 유지 | `npm install`은 기본적으로 `^`를 붙여 범위를 넓힘. 보안 수정이 고정을 풀면 안 됨 |

## 공유 엔진과 변경 경계

클래스나 인터페이스 수를 늘리는 대신 실제 변경 원인이 다른 경계를 분리했습니다.

| 책임 | 소유 위치 | 독립적으로 바꿀 수 있는 것 |
|---|---|---|
| 소스 획득 | `scanner.Scanner` | Git clone 수명·인증. 분석 엔진은 checkout을 소유하지 않음 |
| 분석 | `scanner.Engine` | `fs.FS` → inventory → code graph → matcher → report. 로컬 경로는 `os.Root`로 읽기 경계 제한 |
| scan 조립 | `bootstrap.ScanRuntime` | 웹/CLI의 동일 provider·extractor 기본값. 네트워크 초기화는 `Prepare(ctx)`로 분리 |
| 취약점 조회 | `vulndb` provider/cache 계약, `Matcher.Lookup` | OSV/NVD·KEV/EPSS·저장 어댑터. REST는 단일 조회 계약만 사용 |
| 보고서 저장 | `report.Reader/Store`, `reportstore` | 도메인 report와 Bolt 구현 분리. 기존 JSON/blob 형식 유지 |
| CI 판정 | `scanpolicy` | 심각도 임계값과 검사 완전성. 분석·출력과 분리 |
| 출력 | `output` encoder registry | JSON·Markdown·SARIF와 기존 SBOM encoder를 Strategy로 연결 |
| 조치 실행 | `remediation.StepExecutor`, 단계별 Command registry | 실행 협력자 교체. queue·retry·승인·status 전이는 controller가 소유 |
| UI 전달 | `api-types`, `http`, 기존 `api` facade | URL/오류 계약을 바꾸지 않고 transport와 타입을 분리 |
| UI 계산 | `watch-cache`, `graph-model` | 캐시 정책·그래프 계산을 DOM 없이 검증. React는 연결 수명과 표시를 담당 |

SRP·DIP·ISP를 위 경계에 적용하고, Adapter(저장/소스), Strategy(출력/extractor), Command(조치 단계)를 실제 변동 지점에만 사용합니다. 메모리/Bolt 캐시는 같은 계약 테스트로 입력·반환 객체 격리와 병렬 접근을 확인합니다. 서버 composition의 기존 진입점과 API 타입은 불필요한 호환성 손실을 피하기 위해 유지했습니다.

### 오류와 보안 계약

- OSV 상세 조회 실패·잘못된 응답을 finding 없음으로 바꾸지 않습니다. 취소는 NVD/EPSS 경고로 흡수하지 않습니다.
- 추출 실패를 진단으로 전달합니다. 웹은 보고서 경고를 표시하고 CLI는 불완전 검사를 종료 코드 `2`로 구별합니다.
- CLI/Action은 대상 저장소 코드를 실행하거나 조치하지 않습니다. Action 결과는 checkout 밖의 고유 디렉터리에 둡니다.
- Action의 release 다운로드와 CI 정책 판정은 분리합니다. 보고서 보존 뒤에 실패를 반환하며, SARIF 업로드는 호출자의 선택입니다.
- 프런트 watch의 오래된 이벤트 목록 갱신과 콜백 변경 시 재구독은 기존 정책을 그대로 특성 테스트로 고정했습니다. 이번 책임 추출에 별도 정책 변경을 섞지 않았습니다.

실행법과 배포 전제는 [CLI/Action 문서](../usage/cli-and-actions.md), 승인 범위와 검증 기록은 [리팩토링 기록](cli-action-refactor.md)에 있습니다.

## 검증 기록 (2026-11-22)

- `go test -race ./...` 통과. 끝-대-끝 테스트(`pkg/apiserver`)는 로컬 bare 저장소와 가짜 OSV·NVD·KEV·EPSS·GitHub로 다음 전 구간을 검증:
  - 스캔 → 그래프·SBOM
  - 조치 → 검토 → 승인 → PR(브랜치 push 확인)
  - 웹훅 서명 검증과 재평가 트리거
- 실데이터: `snyk-labs/nodejs-goof` 스캔 결과
  - 컴포넌트 986개, 취약점 254건, KEV 3건
  - body-parser CVE-2024-45590 조치를 실제 Docker 격리 실행으로 검토 단계까지 진행
  - TS-01~04 통과, TS-05는 프로젝트의 `npm test`가 Snyk 로그인을 요구해 실패
  - 남의 저장소이므로 승인·push는 하지 않음
- 브라우저: 홈, 그래프(호버 카드·상세 펼치기), 조치 화면(파이프라인·문서·검토 패널) 확인

## 다음 후보

- 이미지 내부 OS 패키지 스캔(OSV의 Debian/Alpine 데이터 활용)
- Maven/Gradle 의존성 해석기 실행으로 전이 의존성 그래프 확보
- 인증·권한(현재는 단일 사용자용, 루프백 bind 기본)
- 자동 수정이 불가능한 경우(API 파괴적 변경 등)를 위한 코드 수정 에이전트 연동 지점(`fixer.Fixer` 인터페이스)
