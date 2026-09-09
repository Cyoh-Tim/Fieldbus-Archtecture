# CTT lab profile (veth / AF_PACKET / CODESYS)

Phase 3 랩 경로. **기본 CI는 mock** 이다. 이 문서는 실 NIC·veth·CODESYS 를
어떻게 CTT YAML 과 연결하는지 적는다.

PROFINET 범위는 **CC-B + RT Class 1** 만. CC-C / IRT / RT Class 3 랩은 없다.

## 같은 YAML, transport만 교체

```
# CI / 기본 (AF_PACKET·sudo 없음)
./build/ctt --scenario tests/scenarios/profinet/dcp_identify_name_of_station.yaml

# 랩 (veth)
./build/ctt --transport=af_packet --iface=ctt-ctl --dut-iface=ctt-dut \
    --scenario tests/scenarios/profinet/dcp_identify_name_of_station.yaml
```

| 플래그 / env | 의미 |
|--------------|------|
| `--transport=mock` (기본), `CTT_TRANSPORT` | in-process 링. `ctest` 경로 |
| `--transport=af_packet` | Controller AF_PACKET + DUT `pn_eth` |
| `--iface` / `CTT_IFACE` | Controller 쪽 인터페이스 |
| `--dut-iface` / `CTT_DUT_IFACE` | DUT 쪽 인터페이스 (`pn_stack` `iface`) |
| `--capture <dir\|file.pcap>` / `CTT_CAPTURE` | golden 생성용 덤프 |

CMake `-DENABLE_CTT_AF_PACKET=ON` (기본) 이 랩 경로를 컴파일한다.
OFF 이면 `--transport=af_packet` 가 거부된다. **default `ctest` 는 mock 만**
쓰므로 ON/OFF 모두 PR 게이트는 같다.

필요 capability:

- `CAP_NET_ADMIN` — veth 생성 (`ip link add type veth`)
- `CAP_NET_RAW` — `AF_PACKET` SOCK_RAW

## veth 스크립트

```
cmake -S . -B build -DBUILD_DAEMON=OFF -DBUILD_CTT=ON -DENABLE_CTT_AF_PACKET=ON \
    -DBUILD_PN_LAB_TOOLS=ON
cmake --build build
tests/run_ctt_lab.sh
```

스크립트가 하는 일:

1. `ctt-ctl` ↔ `ctt-dut` veth 쌍 생성
2. MAC 을 mock 과 맞춤 (`00:11:22:33:44:55` / `02:fb:00:00:00:01`)
3. **DCP Identify** 시나리오를 같은 YAML 로 실행 (와이어 필수)
4. `rtc1_io_cycle_smoke` — Connect 는 in-process `pn_stack_handle_rpc`,
   RTC1 프레임은 veth

권한이 없으면 **SKIP (exit 0)**. `CTT_LAB_REQUIRE=1` 이면 권한 부족을 실패로 본다.

GitHub Actions 는 `workflow_dispatch` 입력 `lab=true` 로 이 스크립트를 돌린다.
sudo 가 없으면 skip.

## RPC / SNMP 는 아직 실 UDP가 기본이 아님

| 동작 | mock | lab (`af_packet`) |
|------|------|-------------------|
| DCP Identify / Set | mock 링 | veth Ethernet |
| LLDP / Alarm TX / RTC1 | mock 링 | veth Ethernet (AR 은 in-process Connect 후) |
| CM Connect / Release / Record | `pn_stack_handle_rpc` | **같은 훅** (실 UDP 34964 아님) |
| SNMP GET | `pn_stack_handle_snmp` | 같은 훅 (실 UDP 161 아님) |

랩에서 DUT 가 `use_eth_ops=0` 이면 스택이 UDP 34964/161 을 bind 하려고 한다.
CTT Controller stub 은 아직 그 소켓으로 Connect 를 보내지 않는다.
CODESYS 가 Device 로 붙을 때는 아래 `pn_device_run` 경로를 쓴다.

## 기존 수동 도구 (`dcp_probe` / `pn_device_run`)

이 브랜치에 이미 있다. CMake 타깃은 `BUILD_PN_LAB_TOOLS=ON` (기본).
**ctest 에 등록하지 않는다.**

```
# DUT 를 실 iface 에서 poll (unsigned lab Device)
./build/pn_device_run ctt-dut
# 또는
tests/run_pn_device_run.sh ctt-dut

# 점대점 Identify.Req
./build/dcp_probe ctt-ctl
# 또는
tests/run_dcp_probe.sh ctt-ctl
```

CTT `--transport=af_packet` 는 한 프로세스 안에서 Controller stub + DUT 를
veth 양끝에 붙인다. `pn_device_run` + `dcp_probe` 는 **두 프로세스** 점대점
(CODESYS 대향 준비). 시나리오 YAML 은 CTT 쪽이 정본이다.

## CODESYS (Windows) — CI 에 넣지 않음

CODESYS Control Win / SoftPLC 는 이 저장소 CI 에 없다. 랩에서 Device 를
CODESYS Controller 에 붙이려면:

1. Linux 쪽에 `pn_device_run <iface>` 또는 데몬 `config/example.profinet.json`
2. 그 NIC 를 CODESYS 가 있는 네트워크(또는 USB 이더넷 / 브리지)에 연결
3. NameOfStation `sensor-line1`, RT Class 1, cycle 8ms. IRT 프로젝트 쓰지 말 것
4. CTT 는 CODESYS 대신이 아니다. CTT 는 YAML 회귀. CODESYS 는 수동 상호운용

PR #1 랩 자산(프로젝트 파일 등)이 이 브랜치에 없으면, 위 절차만으로 충분하다.
CTT lab profile 이 Identify 를 veth 에서 자동화하고, CODESYS 는 그 다음
수동 게이트다.

## Golden PCAP

`tests/golden/profinet/` 의 파일은 **mock 런에서 생성**한다. NIC 불필요.
재생은 YAML `golden:` 키. 절차는 `tools/ctt/README.md` 와
`tests/regen_ctt_goldens.sh`.

랩 경로에서는 MAC/패딩이 달라질 수 있어 **full-frame golden 을 skip** 한다.
필드 assert (`frame_id`, `name_of_station`) 는 그대로 적용한다.

## 인증과의 관계

랩 green ≠ PI 인증. 매핑은 [`docs/ctt_pi_matrix.md`](ctt_pi_matrix.md).
공식 Test Bundle 접근을 가정하지 않는다. CC-C 카테고리는 매핑하지 않는다.
