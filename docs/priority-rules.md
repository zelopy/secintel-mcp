# 우선순위 규칙

`prioritize_cves`가 CVE에 등급을 매기는 규칙입니다. 판정은 `src/secintel_mcp/priority.py`에서 구현하며, 네트워크 호출 없이 이미 조회한 데이터만으로 이뤄집니다.

## 등급

위에서부터 차례로 검사하고, 처음 해당하는 등급을 부여합니다.

| 등급 | 조건 | 의미 |
| --- | --- | --- |
| P1 | CISA KEV에 등재됨 | 실제 악용이 확인됨 |
| P2 | EPSS ≥ 0.1 **또는** EPSS percentile ≥ 0.95 | 30일 내 악용 가능성이 높음 |
| P3 | CVSS 기본 점수 ≥ 7.0 | 악용되면 피해가 큼 |
| P4 | 위 조건에 모두 해당하지 않음 | 일반 패치 주기로 처리 |
| UNKNOWN | 판정에 필요한 데이터가 없음 | 아래 "데이터가 없을 때" 참고 |

임계값 3개(`epss_threshold`, `percentile_threshold`, `cvss_threshold`)는 도구 인자로 바꿀 수 있습니다. 결과의 `thresholds`에 실제로 쓴 값이 함께 반환됩니다.

### EPSS 기준을 두 개 쓰는 이유

EPSS 점수는 대부분 0 근처에 몰려 있습니다. 절대값 0.1만 쓰면 상위 수 % 안에 드는 CVE도 놓치고, percentile만 쓰면 EPSS 모델이 바뀔 때마다 기준이 함께 움직입니다. 둘 중 하나라도 넘으면 P2로 보고, `reasons`에 어느 기준을 넘었는지 적습니다.

## 판단 근거 (`reasons`)

각 CVE의 `reasons`에는 등급을 정한 근거를 규칙 순서대로 적습니다. 도구 결과는 모델이 읽으므로 영어로 씁니다. 예시는 다음과 같습니다.

- `In CISA KEV since 2021-12-10; known ransomware use; due 2021-12-24`
- `EPSS 0.43 >= 0.1 (percentile 0.99)`
- `CVSS 3.1 9.8 >= 7.0 (NVD)`
- `EPSS 0.002 < 0.1 and percentile 0.41 < 0.95` (P3·P4에서 P2가 아닌 이유)

## NVD 조회 생략

등급은 KEV → EPSS → CVSS 순서로 정해지므로, P1이나 P2로 정해진 CVE는 CVSS가 필요 없습니다. 이 경우 NVD를 호출하지 않고 `cvss_status`를 `skipped`로 둡니다.

NVD는 API 키가 없으면 30초에 5회까지만 요청할 수 있습니다. 30개를 모두 조회하면 3분 가까이 걸리므로, 이 생략이 응답 시간에 큰 차이를 만듭니다.

## CVSS 점수 선택

NVD는 한 CVE에 점수를 여러 개 줄 수 있습니다. 다음 순서로 하나를 고릅니다.

1. 버전: v3.1 → v4.0 → v3.0 → v2.0
2. 같은 버전 안에서는 다음 순서
    1. NVD 자체 분석 (`source_type`이 `Primary`)
    2. CNA 점수 (`Secondary`이면서 `source`가 CVE의 `sourceIdentifier`와 같음)
    3. 그 밖의 제공자 점수 (`Secondary`. 예: CISA ADP)

v3.1을 먼저 쓰는 이유는 두 가지입니다.

- **비교 가능성**: 2026년 10월 초에 게시된 CVE 200건 중 192건에 v3.1 점수가 있고, v4.0은 30건에만 있습니다. v3.1을 먼저 쓰면 대부분의 CVE가 같은 척도로 비교됩니다.
- **버전 간 점수 차이**: 같은 CNA라도 버전에 따라 점수가 크게 다를 수 있습니다. 예를 들어 CVE-2026-105471은 v4.0이 5.5(MEDIUM), v3.1이 7.3(HIGH)입니다. 최신 버전을 먼저 쓰면 v4.0 점수가 있는 CVE만 다른 기준으로 판정됩니다.

v4.0 점수만 있는 CVE는 v4.0을 씁니다.

`Secondary`는 CNA 점수만 뜻하지 않습니다. 예를 들어 log4shell(CVE-2021-44228)의 Secondary 점수는 CNA인 Apache가 아니라 CISA ADP가 매긴 것입니다. 최근 CVE는 NVD 분석이 밀려 Primary 점수가 없는 경우가 많고, 이때 `cvss.source`로 누가 매긴 점수인지 알 수 있습니다.

## 데이터가 없을 때

| 상황 | 처리 |
| --- | --- |
| KEV 피드를 가져오지 못함 (캐시도 없음) | 도구 전체가 에러를 반환합니다. P1 여부를 모르는 채로 P2~P4를 매기면 오해를 부르기 때문입니다 |
| EPSS 점수가 없음 (새 CVE 등) | P2 검사를 건너뛰고 CVSS로 판정합니다. `reasons`에 `No EPSS score`를 적습니다 |
| CVSS가 필요한데 NVD 조회 실패 또는 점수 없음 | `UNKNOWN`. `cvss_status`는 `unavailable` |
| NVD에 없는 CVE | `UNKNOWN`. `reasons`에 `Not found in NVD`를 적습니다 |
| NVD에서 철회된(Rejected) CVE | `UNKNOWN`. `reasons`에 `Rejected in NVD`를 적습니다. 중복 등록 등으로 무효가 된 ID이므로 대체 CVE를 확인해야 합니다 |
| 만료된 캐시로 응답함 | 등급은 그대로 매기고 `warnings`에 데이터 기준 시각을 적습니다 |

## 정렬

결과는 급한 순서로 반환합니다.

1. 등급: P1 → P2 → P3 → P4 → UNKNOWN
2. 같은 P1 안에서는 랜섬웨어 사용이 확인된(`ransomware_use`가 `Known`) CVE가 먼저
3. EPSS 높은 순 (EPSS가 없으면 뒤로)
4. CVSS 높은 순. P1·P2는 NVD 조회를 생략하므로 이 기준은 P3·P4에서만 쓰입니다

## 한계

- KEV에 없다고 악용되지 않았다는 뜻은 아닙니다. KEV는 CISA가 확인한 사례만 담습니다.
- KEV의 랜섬웨어 표시가 `Unknown`이어도 랜섬웨어에 쓰이지 않았다는 뜻은 아닙니다. 그래서 `true`/`false`로 바꾸지 않고 CISA 값을 그대로 반환합니다.
- v4.0 점수만 있는 CVE는 v3.1 기준으로 맞춘 7.0 임계값과 의미가 조금 다를 수 있습니다. `reasons`에 버전을 함께 적어 구분할 수 있게 합니다.
- EPSS는 매일 갱신되므로 같은 CVE의 등급이 날짜에 따라 바뀔 수 있습니다.
- 이 등급은 공개 데이터만으로 계산합니다. 자산의 노출 여부나 중요도는 반영하지 않으므로, 실제 조치 순서는 환경에 맞게 판단해야 합니다.
