# Cassandra 설계 기록

사용법과 구조 개요는 [README](../../README.md), 피드 조사는 [vulnerability-feeds.md](../research/vulnerability-feeds.md)에 있습니다. 이 문서는 README에 없는 **설계 결정과 그 이유**만 기록합니다.

## 핵심 결정

| 결정 | 이유 |
|---|---|
| SBOM(인벤토리)이 스캔 결과의 원본이고, 그래프·CycloneDX·SPDX는 그 뷰 | 하나의 원본에서 파생하므로 그래프와 SBOM이 어긋나지 않음 |
| 버전 범위 판정은 OSV·NVD 서버에 맡김 (`querybatch`, `cpeName`+`isVulnerable`) | 생태계별 버전 규칙(PEP 440, Maven 등)을 직접 구현하면 오판 위험. 로컬 버전 비교는 "가장 가까운 수정 버전" 선택에만 사용 |
| 피드 변경 시 저장된 스캔 전체가 아니라 **해당 패키지를 가진 스캔만** 재평가 | 패키지 키 → 스캔 인덱스(scan controller). 재평가는 clone 없이 저장된 인벤토리로 재매칭 |
| 리소스는 bbolt 위의 제네릭 `Store[T]` + watch | etcd 없이 kube-apiserver의 list+watch, `GuaranteedUpdate`, resourceVersion 의미를 그대로 사용. UI는 SSE watch로 폴링 없이 갱신 |
| 컨트롤러는 client-go workqueue + 재실행 가능한 단계 | 서버가 재시작되면 Running 단계를 Pending으로 되돌려 다시 실행. 모든 단계는 기준 커밋으로 reset 후 실행하므로 멱등 |
| 테스트 실패는 파이프라인을 멈추지 않고 검토로 넘김 | 실패 원인이 프로젝트 자체 문제일 수 있음(예: `npm test`가 `snyk test`). 사람이 판단하고, 승인해도 Draft PR만 만들며 배포하지 않음 |
| 수정 커밋을 **테스트 실행 전에** 먼저 함 | 테스트가 만든 `node_modules`, `target/` 같은 산출물이 커밋에 섞이지 않도록 |
| 비고정 이미지 태그(`latest`, `5`, `1.25`)는 버전 판정을 하지 않음 | 실데이터에서 `mysql:5`를 버전 "5"로 매칭하자 오탐 168건이 나왔음. 대신 "미고정"으로 표시 |
| CVSS v2만 있는 오래된 CVE는 NVD의 v2 등급을 사용 | 실데이터에서 2014–2016년 CVE 89건이 심각도 UNKNOWN으로 나왔음 |
| 정확히 고정된 npm 버전(`"1.9.0"`)은 수정 후에도 정확한 고정 유지 | `npm install`은 기본적으로 `^`를 붙여 범위를 넓힘. 보안 수정이 고정을 풀면 안 됨 |

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
