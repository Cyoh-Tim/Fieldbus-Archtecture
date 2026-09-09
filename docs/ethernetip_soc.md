# EtherNet/IP Statement of Compliance (draft)

이 문서는 ODVA Conformance Test(CT) 제출용 **Statement of Compliance(SOC) 초안**이다.
공식 Declaration of Conformity는 ODVA 멤버십 + 공인 테스트 랩 CT 통과 후 발급된다.
스택만으로 인증서가 발급되지는 않는다.

## Device identity

| Field | Value |
|-------|-------|
| Product Name | FieldbusSensor (config `product_name`) |
| Device Type | 0x0C Communications Adapter (config `device_type`) |
| Vendor ID | config `vendor_id` (예제 43981 — 제품화 시 ODVA 할당 ID 사용) |
| Product Code | config `product_code` |
| EDS | `stacks/ethernetip/eds/FieldbusSensor.eds` |

## Implemented CIP objects

| Class | Name | Instances | Notes |
|-------|------|-----------|-------|
| 0x01 | Identity | 1 | Attr 1–10, 17; Reset; Get_Attributes_All |
| 0x02 | Message Router | 1 | Minimal |
| 0x04 | Assembly | config/in/out | Attr 3 data, 4 size |
| 0x06 | Connection Manager | 1 | Forward Open/Close, Large FO |
| 0x48 | QoS | 1 | DSCP Urgent/Scheduled/High/Low/Explicit (CT defaults) |
| 0x5E | EtherNet/IP Security | 1 | Profile capability advertisement |
| 0xF4 | Port | 1 | Minimal |
| 0xF5 | TCP/IP Interface | 1 | Status/capability + ACD Status/Activity |
| 0xF6 | Ethernet Link | 1 | Speed/flags/MAC |
| 0x109 | LLDP Management | 1 | TX enable/interval/hold/last change (TX-only) |

## Security profiles (Fieldbus repository)

| Class | Name | Wire behavior |
|-------|------|----------------|
| 0 | Open / lab | 무보안 (개발 전용) |
| 1 | Integrity | HMAC-SHA256 PSK. Mutating UCMM / FO에 CPF item `0x00C1` 필수 |
| 2 | Confidentiality path | Class 1 + TLS PSK listener on TCP 2221 |

공식 CIP Security Confidentiality Profile(전체 DTLS I/O, 인증서 수명주기, CT21 보안 스위트)은
제품 프로세스에서 ODVA 스펙/CT에 맞춰 확장한다. 본 스택은 그 경로의 객체·포트·PSK/TLS 기반을 제공한다.

## ODVA 인증 절차 (제품)

1. ODVA 멤버십 및 Vendor ID 확보
2. EDS / SOC 를 제품 값으로 확정
3. EtherNet/IP CT(현재 CT21 계열) + 필요 시 CIP Security CT를 공인 랩에서 수행
4. Declaration of Conformity 등록

PROFINET(PI) 대비 ODVA는 멤버 기반 CT 접근성이 상대적으로 열려 있다고 알려져 있으나,
스펙 라이선스·멤버십·랩 비용은 여전히 제품 프로세스다.
