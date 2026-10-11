#ifndef EIP_TYPES_H
#define EIP_TYPES_H

#include <stddef.h>
#include <stdint.h>

/*
 * EtherNet/IP Device (+ optional Originator) stack capacity.
 * Tuned for many sensors / large process images — raise further via config
 * sizes, not hard-coded point tables in the adapter.
 */

#define EIP_TCP_PORT_DEFAULT     44818
#define EIP_UDP_IO_PORT_DEFAULT  2222
#define EIP_SECURE_PORT_DEFAULT  2221 /* CIP Security–oriented TLS port */

#define EIP_ENCAP_HDR_SIZE       24
#define EIP_CPF_ITEM_HDR         4
#define EIP_FRAME_MAX            65536
#define EIP_TCP_BUF_MAX          8192

/* High-capacity defaults for multi-sensor deployments */
#define EIP_ASSEMBLY_INSTANCES_MAX  64
#define EIP_ASSEMBLY_SIZE_MAX       2048
#define EIP_CLASS1_CONN_MAX         32
#define EIP_CLASS3_SESSIONS_MAX     64
#define EIP_TCP_CLIENTS_MAX         32
#define EIP_TLS_CLIENTS_MAX         16
#define EIP_TAG_NAME_MAX            128
#define EIP_PRODUCT_NAME_MAX        32
#define EIP_PATH_MAX                64
#define EIP_EXPLICIT_DATA_MAX       504
#define EIP_PSK_LEN                 32
#define EIP_HMAC_LEN                32

/* Security class (Fieldbus profile — see docs/ethernetip_stack.md) */
#define EIP_SECURITY_CLASS_0  0 /* lab / open */
#define EIP_SECURITY_CLASS_1  1 /* Integrity PSK (HMAC) */
#define EIP_SECURITY_CLASS_2  2 /* Integrity + TLS confidentiality port */

/* Encapsulation commands (LE on wire) */
#define EIP_CMD_NOP                 0x0000
#define EIP_CMD_LISTSERVICES        0x0004
#define EIP_CMD_LISTIDENTITY        0x0063
#define EIP_CMD_LISTINTERFACES      0x0064
#define EIP_CMD_REGISTERSESSION     0x0065
#define EIP_CMD_UNREGISTERSESSION   0x0066
#define EIP_CMD_SENDRRDATA          0x006F
#define EIP_CMD_SENDUNITDATA        0x0070

/* Encapsulation status (Vol 2) */
#define EIP_ENCAP_STATUS_SUCCESS          0x0000
#define EIP_ENCAP_STATUS_INVALID_CMD      0x0001
#define EIP_ENCAP_STATUS_INVALID_SESSION  0x0064
#define EIP_ENCAP_STATUS_INVALID_LENGTH   0x0065

/* CPF item types */
#define EIP_ITEM_NULL_ADDR          0x0000
#define EIP_ITEM_CONNECTED_ADDR     0x00A1
#define EIP_ITEM_SEQ_ADDR           0x8002
#define EIP_ITEM_UNCONNECTED_DATA   0x00B2
#define EIP_ITEM_CONNECTED_DATA     0x00B1
#define EIP_ITEM_SOCKADDR_OT        0x8000
#define EIP_ITEM_SOCKADDR_TO        0x8001

/* CIP services */
#define CIP_SVC_GET_ATTR_ALL        0x01
#define CIP_SVC_RESET               0x05
#define CIP_SVC_GET_ATTR_SINGLE     0x0E
#define CIP_SVC_SET_ATTR_SINGLE     0x10
#define CIP_SVC_FORWARD_CLOSE       0x4E
#define CIP_SVC_UNCONNECTED_SEND    0x52
#define CIP_SVC_FORWARD_OPEN        0x54
#define CIP_SVC_LARGE_FORWARD_OPEN  0x5B
#define CIP_SVC_REPLY               0x80

/* CIP status */
#define CIP_STATUS_SUCCESS          0x00
#define CIP_STATUS_CONN_FAILURE     0x01
#define CIP_STATUS_PATH_DEST        0x05
#define CIP_STATUS_PATH_SEGMENT     0x04
#define CIP_STATUS_SERVICE_NSUP     0x08
#define CIP_STATUS_ATTR_NSUP        0x14
#define CIP_STATUS_ATTR_READONLY    0x0A
#define CIP_STATUS_INVALID_PARAM    0x20
#define CIP_STATUS_RESOURCE         0x02
#define CIP_EXT_CONN_IN_USE         0x0100
#define CIP_EXT_CONN_NOT_FOUND      0x0107 /* Forward Close: target connection not found */
#define CIP_EXT_CONN_SIZE           0x0109
#define CIP_EXT_OUT_OF_CONNECTIONS  0x0113
#define CIP_EXT_INVALID_APP_PATH    0x0117 /* produced/consumed application path */
#define CIP_EXT_PARAM_ERROR         0x0205 /* parameter error in unconnected request */
#define CIP_EXT_NO_BUFFER           0x0301
#define CIP_EXT_INVALID_SEGMENT     0x0315 /* invalid segment in connection path */

/* Standard objects */
#define CIP_CLASS_IDENTITY          0x01
#define CIP_CLASS_MSG_ROUTER        0x02
#define CIP_CLASS_ASSEMBLY          0x04
#define CIP_CLASS_CONN_MANAGER      0x06
#define CIP_CLASS_QOS               0x48
#define CIP_CLASS_EIP_SECURITY      0x5E
#define CIP_CLASS_PORT              0xF4
#define CIP_CLASS_TCPIP             0xF5
#define CIP_CLASS_ETHERNET_LINK     0xF6
#define CIP_CLASS_LLDP_MGMT         0x109
#define CIP_CLASS_LLDP_DATA_TABLE   0x10A

#define CIP_STATUS_PRIVILEGE        0x0F

/* QoS DSCP defaults (EtherNet/IP Vol2 typical values used in CT manuals) */
#define EIP_DSCP_EXPLICIT           0x1B /* 27 — ListIdentity / UCMM */
#define EIP_DSCP_SCHEDULED          0x2F /* 47 — Class1 scheduled */
#define EIP_DSCP_HIGH               0x2B /* 43 */
#define EIP_DSCP_LOW                0x1F /* 31 */
#define EIP_DSCP_URGENT             0x37 /* 55 */

/* Real-time poll budgets (keep poll_cycle within ~8ms daemon cycle) */
#define EIP_POLL_TCP_BUDGET         8
#define EIP_POLL_UDP_BUDGET         64
#define EIP_POLL_TLS_BUDGET         4

/* TCP DoS limits (lab-overridable via protocol_params) */
#define EIP_IDLE_TIMEOUT_MS_DEFAULT 60000
#define EIP_MAX_CONN_PER_IP_DEFAULT 4

/* Class1 watchdog: close if no O->T for 4*RPI*2^timeout_multiplier (CIP) */
#define EIP_CLASS1_TIMEOUT_MULT_DEFAULT 4

/* Common assembly instance numbers (Rockwell-style defaults, configurable) */
#define EIP_ASM_CONFIG_DEFAULT      100
#define EIP_ASM_OUTPUT_DEFAULT      101 /* O->T consumed by adapter */
#define EIP_ASM_INPUT_DEFAULT       150 /* T->O produced by adapter */

typedef enum {
    EIP_ROLE_ADAPTER = 0,    /* target / server — primary for sensors */
    EIP_ROLE_ORIGINATOR = 1  /* client / scanner — explicit + optional Class1 */
} eip_role_t;

#endif /* EIP_TYPES_H */
