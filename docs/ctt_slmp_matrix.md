# CTT ↔ SLMP Binary 3E 매핑 (내부)

내부 하네스 **준비도** 표다. **Mitsubishi 공식 인증 / 유료 랩 evidence 가
아니다.** 인증 리포트를 이 green 으로 대체하지 않는다.

DUT: `stacks/slmp/` 자체 스택. Binary **3E** 일괄 읽기(`0x0401`) /
쓰기(`0x1401`) 만. 플러그인은 `slmp_encode_batch_*` +
`slmp_stack_handle_request` (TCP 없음).

**ASCII / 4E 는 영구 비목표** (이 제품 사용자 범위). 시나리오는 거절만
고정한다.

커버 열:

| 값 | 의미 |
|----|------|
| mock | in-process inject / 기본 `ctest` |
| N/A | 범위 밖. 구현하지 않음 |

## 시나리오 → 카테고리

| YAML (`tests/scenarios/slmp/`) | 내부 카테고리 | mock | 비고 |
|---------------------------------|---------------|------|------|
| `device_table.yaml` | Device code 표 | mock | D/M/ZR/X, raw `0xA8` |
| `encode_batch_read.yaml` | 3E encode | mock | subheader `0x0050`, cmd `0x0401`/`0x1401` |
| `batch_read_write_loopback.yaml` | Batch R/W + bits + ASCII + X hex | mock | `test_slmp_stack` loopback 을 소켓 없이 이전 |
| `reject_non_3e.yaml` | ASCII/4E/unknown cmd 거절 | mock | create 거절, subheader `0x0054`, cmd `0x0403` → `0xC050` |
| `soak_short.yaml` | batch read soak (내부) | mock | 32 iterations |

## 범위 밖 / N/A

| 카테고리 | 커버 | 메모 |
|----------|------|------|
| 3E ASCII | **N/A** | `slmp_stack_create` 거절 |
| 4E binary / ASCII | **N/A** | 시나리오는 reject only |
| Random R/W (`0x0403` / `0x1402`) | N/A | end `0xC050` |
| Mitsubishi 공식 인증 | N/A | 공인 랩. 이 하네스가 대체하지 않음 |
| Live TCP :5000 in default CI | not yet | inject 훅. PR #3 `test_slmp_stack` 은 localhost TCP 잔여 |

## 이 표가 말해 주지 않는 것

- CTT green 을 Mitsubishi 인증서 대신 제출하지 말 것
- 4E/ASCII 로드맵
