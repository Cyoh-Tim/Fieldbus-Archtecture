# 감사 2026-10-25 — PN 알람 후속 (T12-10 검증), LLDP 오라클 보강 (T12-11 검증)

- 영역: PROFINET RT·알람 / DCP·LLDP (11단계, PR #153·#155 검증)
- 출처: PR #153 (T12-10) 사양 검토 (opus 하위 에이전트, 루틴 재확인), PR #155 (T12-11) 검증
- 기준 커밋: `af26ab4` (main, #153 병합 직후)
- 판단: 검증 담당 (루틴 재현 + p-net 소스 대조)
- 큐 추가: 1개 (A20261025-6 → 큐 93). 오라클 보강 2개 (T12-11 표시)

## A20261025-6. AlarmCRBlockReq 의 RTATimeoutFactor·RTARetries 범위를 검사하지 않는다

**문제:** T12-10 (#153) 은 AlarmCRBlockReq 의 RTATimeoutFactor·RTARetries 를 읽어 알람 재전송에 쓰지만 범위를 보지 않는다.
TF 0 이면 ACK 타이머가 꺼져 재전송·ERR-RTA 경로가 동작하지 않고, Retries 0 이면 첫 DATA 뒤 바로 끊긴다. 범위 밖 Connect 는 거부해야 한다.

**근거 (파일:줄, 기준 커밋 `af26ab4`):** `stacks/profinet/src/pn_rpc.c:560-564` — AlarmCRBlockReq 파싱이 `ar->rta_timeout_factor`·`ar->rta_retries` 를 범위 검사 없이 저장한다.

**재현:** `tests/oracle/test_pn_oracle.py::test_connect_rejects_alarm_cr_out_of_range` 를 `--runxfail` 로 돌린다.

```
AssertionError: PNIOStatus 00000000 (기대 db810407)   # tf0, tf101
AssertionError: PNIOStatus 00000000 (기대 db810408)   # retries2, retries16
```

**기대값과 출처:** 독립 구현 p-net `src/device/pf_cmdev.c` (AlarmCR 검사, `:4040-4075`):
`rta_timeout_factor < 1 || > 0x64` → `CONNECT(0xDB) / PNIO(0x81) / CONN_FAULTY_ALARM_BLOCK_REQ(0x04) / 7`,
`rta_retries < 3 || > 15` → `… / 8`, `max_alarm_data_length < 200 || > 1432` → `… / 10` (`include/pnet_api.h:177`).
같은 파일의 IOCR/AlarmCR 태그 검사(A20261007-1)와 같은 오류 형식이다.

**수정 범위:** `stacks/profinet/`, `tests/`. MaxAlarmDataLength 범위(200..1432 → `/ 10`)도 같이.

**완료 조건:** `test_connect_rejects_alarm_cr_out_of_range` 4개 통과 (`A20261025-6` 표시 삭제), 기본 Connect (TF 1·Retries 3·MaxLen 200) 는 그대로 성공.

## 오라클 보강 — LLDP (T12-11, 큐 33)

PR #155 는 scapy `contrib.lldp` 확인을 `CMakeLists.txt` 의 configure 프로브(병합 정책 밖)로 넣었다. 같은 확인을 오라클로 옮겼다:
- `test_lldp_port_id_is_port_name` — Port ID subtype 7, 값 `port-001` 또는 `port-001.<NameOfStation>` (p-net `pf_lldp.c` legacy/standard).
- `test_lldp_profinet_required_tlvs` — PNO Port Status (OUI `00-0E-CF` subtype 2), PNO Chassis MAC (subtype 5), IEEE 802.3 MAC/PHY (`00-12-0F` subtype 1), Management Address (p-net `pf_lldp_build` 송신 순서).

main 에서 둘 다 실패 (Port ID subtype 3 MAC, Port Status·MAC/PHY·Management Address 없음), #155 빌드에서 통과. `@known_defect("T12-11", …)` 표시로 넣었고 #155 가 함께 지운다.

## 확인 필요 (큐에 넣지 않음)

1. 컨트롤러가 같은 DATA-RTA 를 다시 보낼 때(장치 ACK 유실) 장치가 ACK 를 다시 보내지 않는다. p-net 은 `exp_seq_count_o` 와 같은 seq 면 ACK 를 재송신한다. 재현 하네스를 만들지 않았다.
2. 컨트롤러가 보낸 ERR-RTA 를 무시한다 (p-net `pf_alarm.c:2187-2210` 은 AR abort). 인수인계 T12-10 문구 밖일 수 있다.
3. 정상 Release·같은 컨트롤러 재Connect 때 출력 대체값 미적용 (#153 "발견한 다른 문제" 1·2). 사양 근거(정상 종료 시 출력 동작)를 확인하지 못했다.
4. AlarmSpecifier SequenceNumber 항상 0 (p-net 은 11비트 시퀀스).
