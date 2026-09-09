# third_party/

구매한 벤더 스택(라이선스 코드)을 배치하는 위치.

- EtherNet/IP **런타임과 CTT DUT** 는 `stacks/ethernetip/` 자체 스택이다.
  `third_party/ethernetip_stack/` 은 선택적 교체 자리일 뿐 CTT DUT가 아니다.
- PROFINET 은 여기 두지 않는다. `stacks/profinet/` 자체 스택을 사용.

## 규칙
- 이 디렉토리 하위 내용은 **git에 커밋하지 않는다** (`.gitignore` 참고).
- 코어(`core/`)는 이 디렉토리를 참조하지 않는다.
