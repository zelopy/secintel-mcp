# 도구 명세

secintel-mcp가 제공하는 도구 5개의 입력과 출력입니다. 출력 모델은 `src/secintel_mcp/models.py`에 정의돼 있고, MCP 클라이언트에는 각 도구의 `outputSchema`로 전달됩니다.

모든 도구는 읽기 전용입니다(`readOnlyHint: true`). 외부 공개 API를 호출하는 도구에는 `openWorldHint: true`를 붙입니다. 도구 설명, 필드 설명, 에러 메시지처럼 모델이 읽는 문자열은 영어로 씁니다.

## 공통 규칙

- **CVE ID**: 앞뒤 공백을 지우고 대문자로 바꾼 뒤 `CVE-YYYY-NNNN` 형식인지 검사합니다. 형식이 틀리면 올바른 예시를 담은 에러를 반환합니다.
- **개수 제한**: `get_epss`와 `check_kev`는 한 번에 1~100개, `prioritize_cves`는 1~50개를 받습니다. 개수는 입력 스키마(`minItems`, `maxItems`)에 들어가고, 중복된 ID는 순서를 지키며 하나로 합칩니다. 개수 검사는 중복을 합치기 전에 하므로, 중복을 포함해 상한을 넘으면 거부됩니다. 클라이언트가 스키마만 보고도 미리 막을 수 있게 하려는 순서입니다.
- **시각**: 모든 시각은 UTC입니다. NVD는 시간대 표기 없이 UTC 시각을 주므로 UTC로 해석합니다.
- **에러 메시지**: 모델이 다음에 할 행동을 알 수 있게 씁니다. 예: `NVD rate limit reached. Retry in 30 seconds, or set NVD_API_KEY for a higher limit.`

## 도구 선택 가이드

| 사용자가 가진 정보 | 쓸 도구 |
| --- | --- |
| CVE ID 하나, 상세 정보가 필요함 | `lookup_cve` |
| 패키지 이름과 버전 | `query_package_vulns` → 결과의 `cve_ids`를 `prioritize_cves`로 |
| CVE 여러 개, 무엇부터 패치할지 | `prioritize_cves` |
| 실제 악용 여부만 | `check_kev` |
| 악용 가능성 점수만 | `get_epss` |

## lookup_cve

NVD에서 CVE 한 건의 상세 정보를 가져옵니다.

| 입력 | 타입 | 설명 |
| --- | --- | --- |
| `cve_id` | string | 예: `CVE-2021-44228` |

출력 `CveDetail`

| 필드 | 설명 |
| --- | --- |
| `cve_id`, `description` | 영문 설명 |
| `published`, `last_modified` | NVD 기준 시각 |
| `nvd_status` | `Analyzed`, `Awaiting Analysis`, `Rejected` 등 |
| `cvss` | 대표 점수 하나 (`version`, `base_score`, `severity`, `vector`, `source`, `source_type`). `Secondary`는 CNA나 CISA ADP 같은 다른 제공자의 점수입니다. 선택 규칙은 [priority-rules.md](priority-rules.md#cvss-점수-선택) 참고. 아직 점수가 없으면 null |
| `cwes` | CWE ID 목록 |
| `references` | 최대 10개. `Exploit`, `Patch`, `Vendor Advisory` 태그가 붙은 링크를 먼저 |
| `references_total` | 중복 URL을 뺀 전체 참조 링크 수 (log4shell은 52개). `Broken Link` 태그가 붙은 링크는 맨 뒤로 보냅니다 |

NVD에 없는 CVE를 조회하면 에러를 반환합니다. 게시된 지 몇 시간 안 된 CVE는 아직 NVD에 없을 수 있다는 안내가 함께 갑니다.

## query_package_vulns

OSV에서 패키지 버전에 영향을 주는 취약점을 찾습니다.

| 입력 | 타입 | 설명 |
| --- | --- | --- |
| `ecosystem` | enum | `PyPI`, `npm`, `Maven`, `Go`, `crates.io`, `RubyGems`, `NuGet`, `Packagist` |
| `package` | string | Maven은 `groupId:artifactId` 형식. 예: `org.apache.logging.log4j:log4j-core` |
| `version` | string, 선택 | 생략하면 모든 버전의 취약점을 반환 |

출력 `PackageVulns`

| 필드 | 설명 |
| --- | --- |
| `vulns[]` | `id`(GHSA 등), `cve_ids`, `summary`, `severity`, `fixed_versions`, `published`, `modified`. `cve_ids`에는 CVE 별칭과 함께, 권고 ID 자체가 CVE이면(Debian 등) 그 ID도 들어갑니다 |
| `cve_ids` | 중복을 뺀 CVE ID 전체. `prioritize_cves`에 그대로 넘길 수 있습니다 |
| `without_cve` | CVE ID가 하나도 없는(`cve_ids`가 빈) 권고 수. 이 권고들은 `prioritize_cves`로 판정할 수 없습니다 |

OSV는 CVSS 벡터만 주고 점수는 주지 않습니다. 그래서 `severity`에는 권고 출처가 붙인 등급 문자열(`CRITICAL`, `MODERATE` 등)만 담습니다.

## get_epss

FIRST EPSS 점수를 일괄 조회합니다.

| 입력 | 타입 | 설명 |
| --- | --- | --- |
| `cve_ids` | string[] | 1~100개 |

출력 `EpssResult`

| 필드 | 설명 |
| --- | --- |
| `scores[]` | `cve_id`, `epss`(30일 내 악용 확률, 0~1), `percentile`(점수가 같거나 낮은 CVE의 비율, 0~1), `score_date` |
| `not_found` | 점수가 없는 CVE. 너무 새롭거나, 거부(rejected)됐거나, 존재하지 않는 경우입니다 |

## check_kev

CISA KEV 카탈로그에 등재됐는지 확인합니다.

| 입력 | 타입 | 설명 |
| --- | --- | --- |
| `cve_ids` | string[] | 1~100개 |

출력 `KevResult`

| 필드 | 설명 |
| --- | --- |
| `in_kev[]` | `cve_id`, `vendor_project`, `product`, `vulnerability_name`, `date_added`, `due_date`, `ransomware_use`, `required_action`, `short_description`, `cwes` |
| `ransomware_use` | CISA 값 그대로 `Known` 또는 `Unknown`. `Unknown`은 "확인된 바 없음"이지 "사용되지 않음"이 아닙니다 |
| `not_in_kev` | 등재되지 않은 CVE. 악용되지 않았다는 증거는 아닙니다 |
| `catalog_version`, `catalog_released` | 조회한 카탈로그의 버전과 발행 시각 |

## prioritize_cves

CVE 목록에 P1~P4 등급을 매기고 근거를 함께 반환합니다. 규칙은 [priority-rules.md](priority-rules.md)에 있습니다.

| 입력 | 타입 | 기본값 | 설명 |
| --- | --- | --- | --- |
| `cve_ids` | string[] | | 1~50개 |
| `epss_threshold` | number | 0.1 | P2 기준 EPSS, 0~1 |
| `percentile_threshold` | number | 0.95 | P2 기준 EPSS percentile, 0~1 |
| `cvss_threshold` | number | 7.0 | P3 기준 CVSS, 0~10 |

출력 `PrioritizationResult`

| 필드 | 설명 |
| --- | --- |
| `results[]` | 급한 순서. `cve_id`, `priority`, `reasons`, `in_kev`, `ransomware_use`, `kev_due_date`, `epss`, `epss_percentile`, `cvss`, `cvss_status` |
| `counts` | 등급별 개수 |
| `thresholds` | 실제로 쓴 임계값. 필드 이름이 입력 인자 이름과 같아 그대로 다시 넘길 수 있습니다 |
| `kev_catalog_version`, `epss_date` | 판정에 쓴 데이터의 기준 |
| `warnings` | 만료된 캐시 사용, 일부 소스 실패 등 |

`cvss_status`가 `skipped`이면 KEV나 EPSS로 등급이 이미 정해져 NVD를 조회하지 않은 것입니다. 점수가 필요하면 `lookup_cve`로 따로 조회하면 됩니다.
