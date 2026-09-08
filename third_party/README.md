# third_party/

구매한 벤더 스택(라이선스 코드)을 배치하는 위치.

- `third_party/ethernetip_stack/` — (선택) 향후 벤더 EtherNet/IP 스택 교체용.
  **현재 런타임은 `stacks/ethernetip/` 자체 스택을 사용한다.**
- PROFINET 은 여기 두지 않는다. `stacks/profinet/` 자체 스택을 사용.

## 규칙
- 이 디렉토리 하위 내용은 **git에 커밋하지 않는다** (`.gitignore` 참고).
- 코어(`core/`)는 이 디렉토리를 참조하지 않는다.
