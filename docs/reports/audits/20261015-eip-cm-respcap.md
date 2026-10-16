# 감사 2026-10-15 — EIP Forward Open 성공 응답이 확인한 버퍼보다 4바이트 길다

- 영역: EtherNet/IP 스택 (11단계 제안 선별)
- 출처: PR #124 (T11-5) "발견한 다른 문제" 1
- 기준 커밋: `cc4cc33` (main, #124 병합 직후)
- 판단: 검증 담당 (루틴 직접, ASan 재현)
- 큐 추가: 1개 (A20261015-1 → 큐 81)

## A20261015-1. 표준 Forward Open 성공 응답 30바이트를 26바이트 검사로 쓴다 (힙 오버플로)

**문제:** `eip_cm_forward_open` 은 성공 응답을 쓰기 전에 `need = large ? 30 : 26` 으로 버퍼를 검사하지만, 실제로 쓰는 본문은
표준·Large 모두 30바이트다 (서비스·상태 4 + O→T/T→O ID 8 + triad 8 + RPI 8 + Application Reply Size·reserved 2).
`resp_cap` 이 26~29 이면 검사를 통과하고 버퍼 끝을 최대 4바이트 넘어 쓴다. 지금 호출부(encapsulation 경로)는 568바이트 버퍼를
넘기므로 네트워크 입력으로는 도달하지 않는다. 내부 API 의 메모리 안전 결함이고, 응답 버퍼가 작은 호출부가 생기면 바로 드러난다.

**근거 (파일:줄, 기준 커밋 `cc4cc33`):**
- `stacks/ethernetip/src/eip_cm.c:389` — `size_t need = large ? 30 : 26;`
- 같은 함수의 성공 본문 작성 (`:396` 이후) — 4+4+4+2+2+4+4+4+1+1 = 30바이트.

**재현 (스크래치 하네스, `-fsanitize=address,undefined`, 정확한 크기의 힙 버퍼):**

```
cap=30: rc=0 resp_len=30 status=0x00
cap=28: ERROR: AddressSanitizer: heap-buffer-overflow … WRITE of size 1 … eip_cm_forward_open eip_cm.c:416
cap=26: ERROR: AddressSanitizer: heap-buffer-overflow … WRITE of size 1 … eip_wr_le32 … eip_cm_forward_open eip_cm.c:414
```

**기대값과 출처:** 성공 Forward Open 응답 = 30바이트 (CIP Vol 1 Forward_Open reply: O→T/T→O Connection ID, triad, O→T/T→O API,
Application Reply Size, Reserved). Wireshark `packet-cip.c` 의 성공 FO 응답 디섹션과 같은 배치. 검사 값은 쓰는 길이와 같아야 한다.

**수정 범위:** `stacks/ethernetip/`, `tests/`. `need` 를 30 으로 (표준·Large 같음). 부족하면 기존처럼 슬롯을 되돌리고 `0x01/0x0301`
(그 응답도 16바이트가 필요하므로 `cm_err` 는 빈 응답).

**완료 조건:** 단위 테스트가 `resp_cap` 26·28·29 의 정확한 크기 버퍼로 `eip_cm_forward_open` 을 불러 범위 밖 쓰기가 없고 연결이
설치되지 않음을 보인다 (sanitizers job 의 ASan 이 판정). 30 이상은 지금과 같은 성공 응답.
오라클 표시 없음 (내부 API).
