# tests/oracle — 독립 구현체 교차 확인

스택을 **시험 대상(DUT)으로만** 띄우고, 판정은 저장소 코드를 공유하지 않는 독립 구현체가 한다.
저장소의 CTT·golden·단위 테스트는 스택과 같은 가정을 공유할 수 있어서, 그것만으로는 사양
적합성을 보여 주지 못한다 ([`docs/reports/structure_handoff_20260930.md`](../../docs/reports/structure_handoff_20260930.md) T11-0, T12-0).

| 프로토콜 | 오라클 | DUT | 연결 |
|---|---|---|---|
| Modbus TCP | pymodbus, 사양 기반 가짜 서버 (클라이언트 경로) | `mb_seeded_server`, `mb_oracle_client`, `mb_slmp_oracle_app` | 루프백 TCP |
| SLMP 3E | pymcprotocol (서버 경로), 사양 기반 가짜 PLC (클라이언트 경로) | `slmp_oracle_server`, `slmp_oracle_client`, `mb_slmp_oracle_app` | 루프백 TCP |
| EtherNet/IP | pycomm3, scapy `enipTCP` + 사양 기반 인코더 (Forward Open, Class 1), 가짜 Logix (Originator) | `eip_oracle_adapter`, `eip_oracle_originator`, `eip_oracle_fbapi` | 루프백 TCP/UDP |
| PROFINET | scapy (`pnio`, `pnio_dcp`, `pnio_rpc`, `dcerpc`, `lldp`, `snmp`) | `pn_oracle_pipe`, `pn_oracle_app` | mock Ethernet (stdin/stdout) |

`*_fbapi`, `*_app` DUT 는 공개 `fb_api` 로 설정 파일을 열어 **어댑터까지** 시험한다 (스케일, 주소 파싱, 바이트 순서 등).
cJSON 이 필요해 `BUILD_DAEMON=ON` 에서만 빌드된다.

## 실행

```bash
cmake -S . -B build-oracle -DBUILD_DAEMON=ON -DBUILD_CTT=OFF -DBUILD_PN_LAB_TOOLS=OFF \
      -DENABLE_PN_TESTS=OFF -DENABLE_EIP_TESTS=OFF -DENABLE_MB_TESTS=OFF -DENABLE_SLMP_TESTS=OFF
cmake --build build-oracle -j --target mb_seeded_server mb_oracle_client slmp_oracle_server slmp_oracle_client \
      eip_oracle_adapter eip_oracle_originator pn_oracle_pipe eip_oracle_fbapi mb_slmp_oracle_app pn_oracle_app
python3 -m venv .venv && .venv/bin/pip install -r tests/oracle/requirements.txt
ORACLE_BUILD_DIR=build-oracle .venv/bin/python -m pytest tests/oracle
```

CI 정의는 `.github/workflows/ci.yml` 의 `oracle` job 이다. GitHub Actions 는 2026-09-30 부터 꺼져 있어서,
검증 담당이 `python3 tools/ci/local_ci.py --jobs oracle` (또는 전체 job) 로 같은 명령을 돌린다.

## 랩 테스트 (veth + network namespace)

`test_pn_lab.py`, `test_eip_lab.py` 는 mock 이 아니라 **실제 전송 경로**(AF_PACKET, UDP)를 veth 위에서 돌린다.
DUT 는 namespace 안 veth 에, 상대(컨트롤러·스캐너)는 바깥 veth 에 둔다. 장치 MAC, UDP 목적지 포트, 선로 위 프레임
길이·태그·송신 간격처럼 mock 에서 보이지 않는 동작을 본다.

- **root 와 `ip` 가 필요**하다. 없으면 건너뛴다 (GitHub 러너의 `oracle` job 은 건너뛴다). `tools/ci/local_ci.py` 를
  root 로 돌리면 **PN 랩은 oracle job 안에서 실행된다** (EIP 랩은 `EIP_LAB_SCANNER` 가 있을 때만).
- `test_pn_lab.py`: 컨트롤러는 scapy (`test_pn_oracle.py` 의 요청 인코더 재사용). DUT `pn_oracle_lab`.
- `test_eip_lab.py`: 스캐너는 독립 오픈소스 [EIPScanner](https://github.com/nimbuscontrols/EIPScanner) (MIT, 고정 커밋).
  `tests/oracle/lab/build_eipscanner.sh <dir>` 로 빌드하고 `EIP_LAB_SCANNER=<dir>/eipscanner_originator` 를 준다.

```bash
sudo ORACLE_BUILD_DIR=build-oracle .venv/bin/python -m pytest tests/oracle/test_pn_lab.py
tests/oracle/lab/build_eipscanner.sh /tmp/eiplab
sudo EIP_LAB_SCANNER=/tmp/eiplab/eipscanner_originator ORACLE_BUILD_DIR=build-oracle \
     .venv/bin/python -m pytest tests/oracle/test_eip_lab.py
```

구현 PR 은 자기 T 항목의 표시를 mock 오라클(`test_pn_oracle.py` 등)과 **랩(`test_pn_lab.py`, `test_eip_lab.py`) 양쪽에서** 지운다
(root 로컬 CI 에서 PN 랩이 XPASS 로 실패한다). EIP 랩은 기본 실행에서 건너뛰므로, 검증 담당이 PR 검증 때 돌려 XPASS 를 확인하고
남은 표시가 있으면 PR 에 알리거나 자체 PR 로 지운다.

## 알려진 결함 (`known_defect`)

인수인계 문서의 결함은 `@known_defect("T..", "이유")` 로 표시한 strict xfail 이다.

- 지금은 **실패하는 것이 정상**이고, CI 는 green 이다.
- 결함을 고치면 테스트가 통과(XPASS)하고, strict 설정 때문에 **CI 가 빨간색이 된다.**
  수정 PR 은 해당 `@known_defect` 줄을 지워야 한다. 이것이 "고쳤다" 는 증거가 된다.
- 결함이 고쳐지지 않았는데 표시를 지우면 테스트가 실패한다.
- DUT 실행 파일이 하나라도 없으면 `dut_path` 가 **실행 전체를 중단**한다 (종료 코드 3). DUT 가 없어서 실패한 것이
  xfail(결함 남음)이나 skip 으로 위장되지 않게 하기 위해서다.
- 선행 추가: 큐(`docs/reports/work_queue.md`) 항목은 구현 에이전트가 이슈를 받기 전에 오라클을 먼저 넣는다.
  "오라클 표시" 칸이 그 항목의 표시 수다.

## 규칙

- 오라클 판정 로직에 저장소 코드(`stacks/`, `adapters/`, `tools/ctt/`)를 import 하거나 복사하지 않는다.
- 오라클 라이브러리가 지원하지 않는 요청은 사양을 근거로 이 폴더 안에서 직접 인코딩한다
  (예: `test_eip_oracle.py` 의 Forward Open). 근거가 되는 필드 설명을 주석으로 남긴다.
- 오라클 버전은 `requirements.txt` 에 고정한다. 버전을 올리면 판정 기준이 바뀌므로 별도 PR 로 한다.
- 이 폴더는 검증 담당(Claude)이 관리한다. 구현 PR 은 `@known_defect` 표시 제거만 한다.
