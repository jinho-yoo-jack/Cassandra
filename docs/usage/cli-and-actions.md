# CLI와 GitHub Action

웹 서버를 설치하지 않고 checkout된 디렉터리를 검사합니다. 웹과 CLI는 같은 extractor·코드 그래프·취약점 매칭 엔진을 사용합니다. CLI/Action에는 자동 수정·PR 생성·배포 기능이 없습니다. 기존 웹 서비스의 승인 기반 조치 기능은 그대로 유지됩니다.

## 로컬 실행

소스에서 빌드할 때만 `backend/go.mod`에 명시된 Go 버전이 필요합니다. 실행에는 Node.js, Docker, git, API 서버 또는 데이터베이스가 필요하지 않습니다.

```sh
make cli
backend/bin/cassandra scan --path . --output-dir cassandra-results --fail-on high
backend/bin/cassandra scan --help
```

검사 대상의 install/build/test 스크립트는 실행하지 않습니다. 로컬 디렉터리를 다시 clone하거나 삭제하지 않습니다. 단, **네트워크 없는 오프라인 스캐너는 아닙니다.** 패키지 이름·버전을 OSV에 보내고, 서버 프로세스는 NVD에 조회하며 KEV/EPSS를 사용합니다. Go 모듈 그래프 확장에는 Go proxy를 사용합니다. 전체 소스 코드를 업로드하지는 않습니다.

### 주요 옵션

| 옵션 | 기본값 | 의미 |
|---|---|---|
| `--path` | `.` | 실제 분석할 디렉터리 |
| `--output-dir` | `cassandra-results` | 결과 파일 저장 위치 |
| `--format` | 모든 형식 | `json,markdown,cyclonedx,spdx,sarif` 중 선택 |
| `--fail-on` | `high` | `none,low,medium,high,critical` |
| `--timeout` | `5m` | 네트워크 준비와 분석의 총 시간 제한 |
| `--repository` | `$GITHUB_REPOSITORY` | 선택적 `owner/repo` 메타데이터. 검사 소스를 바꾸지 않음 |
| `--commit`, `--ref` | GitHub 실행 환경 값 | 선택적 checkout 메타데이터. 직접 지정 시 실제 소스와 일치시킬 것 |
| `--go-proxy` | `https://proxy.golang.org` | 빈 문자열이면 Go 그래프 확장 비활성화 |
| `--osv-url`, `--nvd-url`, `--kev-url`, `--epss-url` | 공개 서비스 | 명시적으로 관리하는 프록시/테스트 endpoint 지정 |

선택적 NVD 키는 `NVD_API_KEY` 환경변수로 전달합니다. CLI 플래그나 저장소 파일에 키를 넣지 마세요. 사용자 지정 NVD endpoint에도 키가 전송되므로 신뢰하는 endpoint만 사용해야 합니다.

### 종료 코드와 산출물

출력 경로에 디렉터리 심볼릭 링크가 있으면 거부합니다. 필요한 경우 실제 디렉터리 경로를 사용하세요. 지원 매니페스트를 링크 때문에 건너뛴 경우, companion lockfile을 읽을 수 없는 경우, 해석되지 않은 의존성 선언이나 불완전한 provider 응답은 진단 대상으로 처리합니다. 실제로 의존성이 없는 정상 프로젝트를 일괄 실패시키지는 않습니다.

| 코드 | 의미 |
|---|---|
| `0` | 지원하는 매니페스트를 분석했고 설정한 취약점 정책을 통과 |
| `1` | 임계값 이상의 취약점 발견. 활성화된 임계값에서는 심각도 `UNKNOWN`도 차단 |
| `2` | 사용법·입출력·통신 오류, 시간 초과, 불완전 검사, 지원 매니페스트 없음 |

`--fail-on none`은 **취약점 임계값만** 끕니다. 불완전 검사와 운영 오류를 성공으로 바꾸지 않습니다. 정상 report를 얻었다면 정책 판정 전에 결과를 기록하므로 `1`에서도 산출물이 남고, 부분 결과가 있는 `2`에서도 진단 결과를 확인할 수 있습니다. 초기화나 필수 조회 자체가 실패했다면 report 파일이 생성되지 않을 수 있습니다.

- `report.json`: inventory, code graph, findings, 경고를 포함하는 전체 보고서
- `summary.md`: 최대 200개 finding을 보여주는 요약. 전체 내용은 JSON에 보존
- `sbom.cyclonedx.json`: CycloneDX 1.6
- `sbom.spdx.json`: SPDX 2.3
- `results.sarif`: SARIF 2.1.0. 실제 매니페스트 위치를 사용하며 모르는 줄 번호를 만들지 않음

컨테이너 내부 OS 패키지, 실행하지 않는 Maven/Gradle 해석, 고정되지 않은 이미지 태그 등의 기존 분석 한계는 [README](../../README.ko.md#한계)와 같습니다. 취약점 미발견은 모든 보안 문제가 없다는 보증이 아닙니다. PR 차이만 검사하는 baseline 비교 기능은 아직 없습니다.

## GitHub Actions에서 사용

Action은 별도 [cassandra-action](https://github.com/jinho-yoo-jack/cassandra-action) 저장소에서 배포하며, CLI 바이너리는 이 저장소의 Releases에서 받습니다. 아래는 첫 릴리스 `v0.1.0`을 사용하는 예시입니다. 운영 workflow에서는 Action 태그를 검토한 커밋의 전체 SHA로 고정하는 것을 권장합니다. 두 릴리스가 게시되고 해당 저장소의 소비자 CI가 통과한 버전을 사용하세요.

```yaml
name: Cassandra scan
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '17 2 * * *'
  workflow_dispatch:
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
        with:
          persist-credentials: false
      - uses: jinho-yoo-jack/cassandra-action@v0.1.0
        id: cassandra
        continue-on-error: true
        with:
          version: v0.1.0
          path: .
          fail-on: high
          timeout: 5m
      - name: Keep reports even when the policy fails
        if: always() && steps.cassandra.outputs.output-dir != ''
        uses: actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f # v6
        with:
          name: cassandra-reports
          path: ${{ steps.cassandra.outputs.output-dir }}
          if-no-files-found: warn
      - name: Enforce the scanner result
        if: always()
        env:
          SCAN_EXIT_CODE: ${{ steps.cassandra.outputs.exit-code }}
          SCAN_OUTCOME: ${{ steps.cassandra.outcome }}
        shell: bash
        run: |
          case "$SCAN_OUTCOME:$SCAN_EXIT_CODE" in
            success:0) exit 0 ;;
            failure:1) exit 1 ;;
            *) exit 2 ;;
          esac
```

`continue-on-error`는 산출물 저장을 위한 것이며 마지막 판정 단계를 빼면 안 됩니다. 기본 검사에는 비밀값이나 쓰기 권한이 필요하지 않습니다. 비공개 저장소 checkout 권한은 호출 workflow가 관리합니다. 선택적으로 `nvd-api-key: ${{ secrets.NVD_API_KEY }}`를 전달할 수 있지만 포크 PR에서는 제공되지 않을 수 있으며 키 없이도 검사할 수 있습니다.

Action은 Linux X64/ARM64를 지원합니다. `version`은 정확한 `vMAJOR.MINOR.PATCH` 또는 prerelease 태그여야 하며 `latest`, `main`, `v1`은 거부합니다. 바이너리와 `checksums.txt`를 HTTPS로 다운로드해 체크섬을 검증합니다. 체크섬은 다운로드 손상 검증이지, 릴리스 작성자나 GitHub 계정이 침해되지 않았다는 증명은 아닙니다.

결과는 checkout 밖의 `$RUNNER_TEMP` 고유 디렉터리에 저장하고 Markdown을 Job Summary에 추가합니다. 출력: `exit-code`, `output-dir`, `report-file`, `sarif-file`, `cyclonedx-file`, `spdx-file`, `summary-file`. 파일 경로 출력이 존재하더라도 초기 실패 시 해당 파일이 없을 수 있습니다.

runner 출력 채널의 영구적인 오류에서는 출력값을 보장할 수 없습니다. 예제처럼 `steps.cassandra.outcome`과 종료 코드를 함께 판정해야 실패한 단계의 오래된 `0` 출력이 성공으로 처리되지 않습니다. `continue-on-error`에 영향받는 `conclusion`은 이 대조에 사용하지 않습니다.

### Code scanning 연동은 선택 사항

SARIF를 GitHub Security 탭에 올리려면 해당 job에 `security-events: write` 권한과 저장소의 Code scanning 사용 조건이 필요합니다. 비공개/내부 저장소는 GitHub Code Security 활성화가 필요할 수 있습니다. 다음 단계를 마지막 정책 판정 **앞에** 추가합니다.

```yaml
      - name: Upload complete SARIF analysis
        if: >-
          always() &&
          ((steps.cassandra.outcome == 'success' && steps.cassandra.outputs.exit-code == '0') ||
          (steps.cassandra.outcome == 'failure' && steps.cassandra.outputs.exit-code == '1')) &&
          (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)
        uses: github/codeql-action/upload-sarif@800a1d8701a65d150a672fef0923dbf2660a62ec # v4
        with:
          sarif_file: ${{ steps.cassandra.outputs.sarif-file }}
          category: cassandra
```

불완전한 검사(`2`)를 업로드해 기존 경고를 지우지 않도록 조건을 유지하세요. 포크 PR의 권한 문제를 피하려고 `pull_request_target`에서 PR 코드를 실행하지 마세요. SARIF 업로드 없이도 JSON·SBOM·Summary·artifact로 사용할 수 있습니다. 세부 조건은 [GitHub SARIF 업로드 문서](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)를 확인하세요.

## 유지관리자: 패키징과 릴리스

```sh
make test
make release VERSION=v0.1.0
```

`dist/`에 Linux/macOS 각각 amd64/arm64 archive와 `checksums.txt`가 생성됩니다. 이 명령은 로컬 파일만 만들며 Git 이력을 변경하지 않습니다. `.github/workflows/ci.yml`은 테스트, 웹 빌드, archive 체크섬과 Linux 실행 파일을 검사합니다. 압축 해제된 실행 파일은 `scripts/smoke_scan.py`의 명시적 로컬 HTTP fixture로 실제 스캔 경로와 종료 코드 0/1/2도 검사합니다. Action wrapper 계약 및 실제 소비자 workflow 검증은 `cassandra-action` 저장소가 담당합니다.

`.github/workflows/release.yml`은 **버전 태그를 push했을 때** 테스트 후 해당 태그의 CLI 릴리스를 게시합니다. Marketplace 등록은 별도 Action 저장소의 릴리스 페이지에서 수행하며, CLI Release 생성만으로 등록되지 않습니다. 게시 후 별도 소비자 workflow 실행·artifact 보존과 선택적인 SARIF 권한을 확인해야 해당 원격 통합을 검증했다고 할 수 있습니다.
