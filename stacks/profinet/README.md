# PROFINET IO Device 스택

이 디렉토리는 Fieldbus Architecture 데몬이 쓰는 **자체 구현 PROFINET IO Device**
입니다. 컨트롤러/스캐너는 없고, 구매 벤더 스택도 쓰지 않습니다.

- 프로토콜을 모르는 사람을 위한 해설: **[GUIDE.md](GUIDE.md)** (이 소스 코드를 예로 듦)
- 랩 구현 범위 표(CC-A/B/C, 인증이 아닌 것): [`docs/profinet_stack.md`](../../docs/profinet_stack.md)
- CODESYS 2시간 데모 붙이는 법: [`docs/codesys_beta.md`](../../docs/codesys_beta.md)
- GSDML: [`gsdml/GSDML-V2.35-Fieldbus-PN-Device.xml`](gsdml/GSDML-V2.35-Fieldbus-PN-Device.xml)

공개 API는 `include/pn_stack.h` 의 `pn_stack_create()` 하나와 그 주변입니다.
데몬에 붙는 쪽은 `adapters/profinet/profinet_adapter.c` 입니다.
