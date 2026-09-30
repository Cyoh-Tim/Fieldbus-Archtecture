# tests/oracle — 독립 구현체 교차 확인

스택을 **시험 대상(DUT)으로만** 띄우고, 판정은 저장소 코드를 공유하지 않는 독립 구현체가 한다.
저장소의 CTT·golden·단위 테스트는 스택과 같은 가정을 공유할 수 있어서, 그것만으로는 사양
적합성을 보여 주지 못한다 ([`docs/reports/structure_handoff_20260930.md`](../../docs/reports/structure_handoff_20260930.md) T11-0, T12-0).

| 프로토콜 | 오라클 | DUT | 연결 |
|---|---|---|---|
| Modbus TCP | pymodbus | `mb_seeded_server` | 루프백 TCP |
| SLMP 3E | pymcprotocol | `slmp_oracle_server` | 루프백 TCP |
| EtherNet/IP | pycomm3 + 사양 기반 인코더 (Forward Open, Class 1) | `eip_oracle_adapter` | 루프백 TCP/UDP |
| PROFINET | scapy (`pnio`, `pnio_dcp`, `pnio_rpc`, `lldp`) | `pn_oracle_pipe` | mock Ethernet (stdin/stdout) |

## 실행

```bash
cmake -S . -B build-oracle -DBUILD_DAEMON=OFF -DBUILD_CTT=OFF -DBUILD_PN_LAB_TOOLS=OFF \
      -DENABLE_PN_TESTS=OFF -DENABLE_EIP_TESTS=OFF -DENABLE_MB_TESTS=OFF -DENABLE_SLMP_TESTS=OFF
cmake --build build-oracle --target mb_seeded_server slmp_oracle_server eip_oracle_adapter pn_oracle_pipe
python3 -m venv .venv && .venv/bin/pip install -r tests/oracle/requirements.txt
ORACLE_BUILD_DIR=build-oracle .venv/bin/python -m pytest tests/oracle
```

CI 는 `.github/workflows/ci.yml` 의 `oracle` job 이 같은 명령을 돌린다.

## 알려진 결함 (`known_defect`)

인수인계 문서의 결함은 `@known_defect("T..", "이유")` 로 표시한 strict xfail 이다.

- 지금은 **실패하는 것이 정상**이고, CI 는 green 이다.
- 결함을 고치면 테스트가 통과(XPASS)하고, strict 설정 때문에 **CI 가 빨간색이 된다.**
  수정 PR 은 해당 `@known_defect` 줄을 지워야 한다. 이것이 "고쳤다" 는 증거가 된다.
- 결함이 고쳐지지 않았는데 표시를 지우면 테스트가 실패한다.

## 규칙

- 오라클 판정 로직에 저장소 코드(`stacks/`, `adapters/`, `tools/ctt/`)를 import 하거나 복사하지 않는다.
- 오라클 라이브러리가 지원하지 않는 요청은 사양을 근거로 이 폴더 안에서 직접 인코딩한다
  (예: `test_eip_oracle.py` 의 Forward Open). 근거가 되는 필드 설명을 주석으로 남긴다.
- 오라클 버전은 `requirements.txt` 에 고정한다. 버전을 올리면 판정 기준이 바뀌므로 별도 PR 로 한다.
- 이 폴더는 검증 담당(Claude)이 관리한다. 구현 PR 은 `@known_defect` 표시 제거만 한다.
