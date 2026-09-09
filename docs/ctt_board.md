# CTT 테스트 보드

내부 시나리오 현황을 브라우저에서 보는 보드다. **CLI CTT 엔진을 대체하지 않는다.**
PI / ODVA / Modbus.org / Mitsubishi **인증 evidence 가 아니다.**

장비 없는 제품 데모의 3번째 화면이다. 스크립트: [`docs/demo.md`](demo.md).
JSON 애니메이션: [`json-config-flow.html`](json-config-flow.html).

| 파일 | 역할 |
|------|------|
| [`docs/ctt_board.html`](ctt_board.html) | 보드 UI (빌드 없이 브라우저에서 열기) |
| [`docs/ctt_board_data.json`](ctt_board_data.json) | 생성 데이터 (HTML 이 fetch, 실패 시 HTML 에 임베드) |
| `tools/ctt/gen_board_data.py` | YAML + 매트릭스 → JSON/임베드 |

## 배지

CMake `BUILD_CTT` 의 `add_test` / `LABELS` 와 기본 CI
`ctest -LE soak_ci` 를 기준으로 분류한다. 이 HTML 이 ctest 를 실행하지는 않는다.

| 배지 | 의미 |
|------|------|
| **통과 (pass)** | `tests/scenarios/<proto>/*.yaml` 이 CMake 에 등록되고, `soak_ci` 라벨이 없어 기본 mock CI 에 포함 |
| **건너뜀 (skip)** | opt-in. `soak_ci` (30s, `-L soak_ci`), `nightly/` (CMake GLOB 밖), lab (`CAP_NET_RAW`, `tests/run_ctt_lab.sh`) |
| **갭 (gap)** | 매트릭스 DUT-not-implemented / not yet (MRP, FSU, CIP TLS mock 미연결 등) |
| **범위 밖 (out_of_scope)** | CC-C/IRT, 공식 PI Bundle / ODVA CT, EtherCAT, Modbus RTU, SLMP ASCII/4E 등 |

PROFINET 시나리오 YAML 에 `golden:` 이 있으면 CMake 가 `LABELS golden` 을 붙인다.
golden 도 기본 `ctest -LE soak_ci` 에 포함되므로 보드는 **통과** 다.

## 데이터 재생성

저장소 루트에서 (Python 3, 표준 라이브러리만):

```
python3 tools/ctt/gen_board_data.py
```

`docs/ctt_board_data.json` 을 다시 쓰고, `docs/ctt_board.html` 안의 임베드 JSON 을
갱신한다. HTML 만 복사해도 `file://` 에서 열린다. HTTP 로 `docs/` 를 서빙하면
최신 JSON 을 fetch 한다.

커밋된 JSON 이 트리와 맞는지:

```
python3 tools/ctt/gen_board_data.py --check
```

시나리오 YAML 이나 `docs/ctt_*_matrix.md` 를 바꾸면 보드 데이터도 같이 재생성해
커밋한다. `BUILD_CTT` 일 때 `ctest -R ctt_board_data_fresh` 가 같은 `--check` 를
돌린다.

## 관련 문서

- [`docs/ctt.md`](ctt.md) — CTT 설계
- [`docs/ctt_pn_bundle.md`](ctt_pn_bundle.md) — PN 내부 bundle v1 (≠ PI 인증)
- [`docs/ctt_eip_bundle.md`](ctt_eip_bundle.md) — EIP 내부 bundle v1 (≠ ODVA 인증)
- [`docs/ctt_mb_bundle.md`](ctt_mb_bundle.md) — Modbus TCP 내부 bundle v1 (≠ Modbus.org 인증)
- [`docs/ctt_slmp_bundle.md`](ctt_slmp_bundle.md) — SLMP 3E 내부 bundle v1 (≠ Mitsubishi 인증)
- [`docs/ctt_pi_matrix.md`](ctt_pi_matrix.md) · [`docs/ctt_odva_matrix.md`](ctt_odva_matrix.md)
- [`docs/ctt_modbus_matrix.md`](ctt_modbus_matrix.md) · [`docs/ctt_slmp_matrix.md`](ctt_slmp_matrix.md)
- [`docs/ctt_lab.md`](ctt_lab.md) — lab / AF_PACKET
