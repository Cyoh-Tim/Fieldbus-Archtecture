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
3. IPv4 `192.168.200.1/24` (ctl) / `192.168.200.2/24` (dut)
   (`CTT_LAB_CTL_IP` / `CTT_LAB_DUT_IP`)
4. DCP Identify / Get / Signal / Hello / Set IP, LLDP (이더넷)
5. SNMP GET sysName — **UDP 161**
6. CM Connect / Write / ParameterEnd / ApplicationReady / Read / Release —
   **UDP 34964**. RTC1·Alarm 프레임은 veth

`device.ip` 가 YAML 에 있으면 lab 에서 실 UDP 를 쓴다. 없으면 mock 과 같이
`pn_stack_handle_rpc` / `pn_stack_handle_snmp` 훅이다.

권한이 없으면 **SKIP (exit 0)**. `CTT_LAB_REQUIRE=1` 이면 권한 부족을 실패로 본다.

GitHub Actions 는 `workflow_dispatch` 입력 `lab=true` 로 이 스크립트를 돌린다.
sudo 가 없으면 skip.

Soak YAML 은 랩에서 돌리지 않는다 (mock `ctest` / `-L soak_ci`).

## RPC / SNMP transport

| 동작 | mock | lab (`af_packet` + `device.ip`) |
|------|------|----------------------------------|
| DCP Identify / Get / Set / Signal / Hello | mock 링 | veth Ethernet |
| LLDP / Alarm TX / RTC1 | mock 링 | veth Ethernet |
| CM Connect / Write / Control / Read / Release | `pn_stack_handle_rpc` | **UDP 34964** |
| ApplicationReady (Device → Controller) | `pn_stack_take_rpc_tx` | DUT `sendto` last RPC peer |
| SNMP GET | `pn_stack_handle_snmp` | **UDP 161** |

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

CODESYS Control Win / SoftPLC / Development System 은 이 저장소 CI 에 없다.
GitHub Actions 에서 Windows CODESYS 를 실행하지 않는다.

**Linux SoftPLC 를 Modbus TCP 마스터로** 두는 DUT 경로(앱 다운로드는 IDE 수동):
[`docs/codesys_master_io.md`](codesys_master_io.md),
`examples/run_codesys_dut.sh`. 스탠드인 마스터는 CODESYS 가 아니다.

랩에서 Device 를 CODESYS Controller 에 붙이려면 체크리스트 스크립트:

```
tests/codesys_manual_lab.sh           # print checklist
tests/codesys_manual_lab.sh eth0      # then start pn_device_run
```

수동 순서 (요약):

1. Linux: `pn_device_run <iface>` 또는 데몬 `config/example.profinet.json`
2. 그 NIC 를 CODESYS 가 있는 네트워크(USB 이더넷 / 브리지)에 연결
3. GSDML: `stacks/profinet/gsdml/GSDML-V2.35-Fieldbus-PN-Device.xml`
4. NameOfStation `sensor-line1`, RT Class 1, cycle 8ms. **IRT 프로젝트 쓰지 말 것**
5. Engineering 스캔 → DCP Identify → 필요 시 Set IP
6. 기대 CM 시퀀스 (CTT `rpc_write_prmend_appready.yaml` 과 같음):
   Connect → Write(옵션) → ParameterEnd → Device ApplicationReady → RTC1
7. CTT 는 CODESYS 대신이 아니다. CTT 는 YAML 회귀. CODESYS 는 수동 상호운용

PASS 메모 (인증 evidence 아님): Identify 로 이름 확인, AR + cyclic IO,
PrmEnd/AppReady 가 fault 가 아님. IRT/PTCP/CC-C 를 켜지 말 것.

## Golden PCAP

`tests/golden/profinet/` 의 파일은 **mock 런에서 생성**한다. NIC 불필요.
재생은 YAML `golden:` 키. 절차는 `tools/ctt/README.md` 와
`tests/regen_ctt_goldens.sh`.

랩 경로에서는 MAC/패딩이 달라질 수 있어 **full-frame golden 을 skip** 한다.
필드 assert (`frame_id`, `name_of_station`) 는 그대로 적용한다.

## 인증과의 관계

랩 green ≠ PI 인증. 매핑은 [`docs/ctt_pi_matrix.md`](ctt_pi_matrix.md).
공식 Test Bundle 접근을 가정하지 않는다. CC-C 카테고리는 매핑하지 않는다.
MRP / Fast Start-Up 은 DUT 미구현이다 (하네스 공백으로 적지 않음).

## Live TCP (기본 CI 밖)

CTT YAML 은 `handle_adu` / `handle_request` / Encaps inject 다. **`:502` /
`:5000` 를 기본 `ctest -LE soak_ci` 에 넣지 않는다.**

이미 있는 localhost 경로 (CTT 시나리오 아님):

| 경로 | 포트 | 언제 |
|------|------|------|
| `fake_sensor_app` Modbus | `127.0.0.1:15560` | `examples/run_mock_flow.sh modbus` |
| CODESYS-shaped Modbus stand-in | `127.0.0.1:15560` | `examples/run_codesys_dut.sh --stand-in` (**SoftPLC 아님**) |
| software master Modbus | `127.0.0.1:15560` | `examples/run_sw_master_soak.sh modbus` |
| software master SLMP 3E | `127.0.0.1:15561` | `examples/run_sw_master_soak.sh slmp` |
| software master EIP Class1 | `127.0.0.1:15562` TCP / `15563` UDP | `examples/run_sw_master_soak.sh ethernetip` (`mock: false`, **CAP_NET_RAW 없음**) |
| `fake_sensor_app` SLMP lab 서버 | `127.0.0.1:15561` | `examples/run_mock_flow.sh slmp` |
| `test_slmp_stack` client/server loopback | `127.0.0.1:15557` | `ctest -R test_slmp_stack` (daemon job) |
| 데몬 `example.modbus.json` | 설정 포트 (예: 1502) | 수동 |

수동 스모크 (CI 게이트 아님):

```
./build/fake_sensor_app --seconds 5 config/example.fake_sensor.json
# 다른 터미널에서 Modbus TCP 클라이언트로 127.0.0.1:15560
```

제품 well-known 포트(`:502` / Mitsubishi `:5000`) 를 기본 게이트에 바인드하지
않는다. 권한·포트 충돌을 PR CI 에 넣지 않기 위함이다.

