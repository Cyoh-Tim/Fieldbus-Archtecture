# CTT ↔ Modbus TCP 매핑 (내부)

내부 하네스 **준비도** 표다. **Modbus.org 공식 conformance / 유료 랩 인증
evidence 가 아니다.** 인증 리포트를 이 green 으로 대체하지 않는다.

DUT: `stacks/modbus/` 자체 TCP 서버 (`mb_stack_handle_adu`). 데몬도 동일 스택
(`adapters/modbus/`, libmodbus 없음). **RTU 는 범위 밖.**

내부 bundle-grade 카탈로그: [`docs/ctt_mb_bundle.md`](ctt_mb_bundle.md)
(`MB-T-*`, **≠ Modbus.org 인증**).

커버 열:

| 값 | 의미 |
|----|------|
| mock | `./build/ctt --transport=mock` / 기본 `ctest` (`handle_adu` inject) |
| not yet | YAML 없음. 후속 |
| N/A | 제품·CTT 범위 밖 |

## 시나리오 → 카테고리

| YAML (`tests/scenarios/modbus/`) | 내부 카테고리 | mock | 비고 |
|-----------------------------------|---------------|------|------|
| `fc03_read_holding.yaml` | FC03 Holding | mock | `MB-T-FC-001` |
| `fc05_write_single_coil.yaml` | FC05 Coil | mock | `MB-T-FC-002` |
| `fc22_mask_write.yaml` | FC22 Mask Write | mock | `(cur & and)` then OR `(or & ~and)`. `MB-T-FC-003` |
| `fc_server_matrix.yaml` | FC01–04, 06, 0F, 10, 16, 17, bulk 125, illegal FC, wrong unit | mock | `MB-T-FC-004` |
| `string_bytes.yaml` | Packed ASCII | mock | `MB-T-FC-005` |
| `holding_lifetime.yaml` | Holding write/read lifetime | mock | FC16→FC03→wrong unit→overwrite. `MB-T-CM-001` |
| `coil_lifetime.yaml` | Coil write/read lifetime | mock | FC05→FC01→wrong unit→overwrite. `MB-T-CM-002` |
| `fc03_cyclic_metrics.yaml` | FC03 cyclic metrics | mock | 48 cycles, late/missed/jitter. `MB-T-CYC-002` |
| `fc03_cycle_4ms.yaml` | FC03 4 ms metrics | mock | 48×4ms. `MB-T-CYC-003` |
| `soak_short.yaml` | FC03 soak (내부) | mock (`ctest`) | 32 iterations + metrics. `MB-T-CYC-001` |
| `nightly/soak_nightly.yaml` | FC03 soak 1h | 수동 mock | `MB-T-CYC-012`. ctest 미등록. `--seconds` 로 덮어씀 |
| `exception_illegal_address.yaml` | Exception 0x02 / illegal FC | mock | Holding/Coil OOB, qty=0. `MB-T-NEG-001` |
| `adu_malformed.yaml` | Truncated / bad MBAP | mock | fail closed. `MB-T-NEG-002` |
| `exception_illegal_value.yaml` | Exception 0x03 | mock | bad coil value / short PDU. `MB-T-NEG-003` |

## 범위 밖 / N/A

| 카테고리 | 커버 | 메모 |
|----------|------|------|
| Modbus RTU / serial | N/A | TCP only |
| Official Modbus.org conformance lab | N/A | 유료/랩 프로세스. 이 하네스가 대체하지 않음 |
| Live TCP :502 in default CI | not yet | inject 훅. 라이브는 데몬/`fake_sensor` `:15560`. **기본 ctest 에 `:502` 없음** |
| FC08 Diagnostics / FC11/12 / MEI (FC43) | **DUT not implemented** | illegal FC 로만 고정. 가짜 pass 금지 |
| Encapsulated RTU / UDP | N/A | |

## 이 표가 말해 주지 않는 것

- CTT green 을 Modbus.org 인증서 대신 제출하지 말 것
- 공식 TC 번호·공인 랩 판정
