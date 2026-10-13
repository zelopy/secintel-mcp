# secintel-mcp

> 🚧 개발 중입니다. 아래 도구와 설치 방법은 목표 사양이며, 아직 배포되지 않았습니다.

공개 취약점 인텔리전스(NVD, OSV, FIRST EPSS, CISA KEV)를 AI 에이전트가 사용할 수 있도록 제공하는 [MCP(Model Context Protocol)](https://modelcontextprotocol.io) 서버입니다.

CVE 정보 조회, 패키지 버전별 취약점 확인, 실제 악용 여부와 악용 가능성 점수 확인에 더해, 여러 CVE 중 **무엇부터 패치해야 하는지**를 판단 근거와 함께 알려 줍니다.

## 이런 질문에 답합니다

- "log4j-core 2.14.1을 쓰고 있는데 위험한가요?"
- "CVE-2022-22965(Spring4Shell)가 실제로 악용되고 있나요?"
- "이 CVE 5개 중 무엇부터 패치해야 하나요?"

## 도구

| 도구 | 데이터 소스 | 역할 |
|---|---|---|
| `lookup_cve` | NVD API 2.0 | CVE 설명, CVSS, CWE, 참조 링크 |
| `query_package_vulns` | OSV API | 생태계·패키지·버전 기준 취약점 조회 |
| `get_epss` | FIRST EPSS | 악용 가능성 점수 (일괄 조회) |
| `check_kev` | CISA KEV | 실제 악용 확인 여부 |
| `prioritize_cves` | 위 4개 조합 | 우선순위 등급과 판단 근거 반환 |

모든 도구는 읽기 전용이며, 공개 API만 호출합니다.

## 우선순위 규칙

`prioritize_cves`는 다음 순서로 등급을 매기고, 어떤 조건에 해당했는지를 결과에 함께 반환합니다.

| 등급 | 조건 |
|---|---|
| P1 | CISA KEV에 등재됨 (실제 악용이 확인됨) |
| P2 | EPSS ≥ 0.1 또는 EPSS percentile ≥ 0.95 |
| P3 | CVSS ≥ 7.0 |
| P4 | 그 외 |

- 임계값은 설정이나 도구 인자로 변경할 수 있습니다.
- KEV와 EPSS만으로 등급이 정해진 CVE는 NVD를 조회하지 않습니다. 따라서 NVD 요청 한도에 걸리지 않고 더 빨리 응답합니다.

패키지 단위로 우선순위를 매기려면 에이전트가 `query_package_vulns`로 CVE 목록을 얻은 뒤 `prioritize_cves`에 넘기면 됩니다.

## 설치 (예정)

```bash
uvx secintel-mcp
```

Claude Desktop 설정 예시 (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "secintel": {
      "command": "uvx",
      "args": ["secintel-mcp"],
      "env": { "NVD_API_KEY": "<선택: NVD API 키>" }
    }
  }
}
```

NVD API 키가 없어도 동작합니다. 다만 키가 없으면 NVD 요청 한도가 30초당 5회로 제한되므로, [NVD에서 무료 키를 발급](https://nvd.nist.gov/developers/request-an-api-key)받아 쓰는 것을 권장합니다.

## 기술 스택

Python 3.11+, [uv](https://docs.astral.sh/uv/), [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) 2.x (`MCPServer`), httpx, pytest

## 로드맵

- [ ] 도구 5개 최소 동작 버전
- [ ] KEV·EPSS 일 단위 캐시, NVD 재시도·백오프
- [ ] 공개 CVE 기반 평가셋과 CI
- [ ] PyPI 배포
- [ ] Semgrep·Trivy 결과 파싱 도구 (취약점 트리아지 에이전트로 확장)

## 데이터 출처

- [NVD](https://nvd.nist.gov/) — This product uses the NVD API but is not endorsed or certified by the NVD.
- [OSV](https://osv.dev/)
- [FIRST EPSS](https://www.first.org/epss/)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

이 도구의 결과는 패치 우선순위를 판단하는 데 참고하는 자료입니다. 실제 조치는 각 환경에 맞게 검토한 뒤 결정하세요.

## 라이선스

MIT
