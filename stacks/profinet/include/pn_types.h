#ifndef PN_TYPES_H
#define PN_TYPES_H

#include <stddef.h>
#include <stdint.h>

#define PN_ETHTYPE_PN         0x8892u
#define PN_ETHTYPE_LLDP       0x88CCu
#define PN_ETHTYPE_VLAN       0x8100u

#define PN_FRAMEID_DCP_HELLO  0xFEFCu
#define PN_FRAMEID_DCP_GETSET 0xFEFDu
#define PN_FRAMEID_DCP_ID_REQ 0xFEFEu
#define PN_FRAMEID_DCP_ID_RES 0xFEFFu
#define PN_FRAMEID_ALARM_HIGH 0xFC01u
#define PN_FRAMEID_ALARM_LOW  0xFE01u

#define PN_DCP_GET            0x03u
#define PN_DCP_SET            0x04u
#define PN_DCP_IDENTIFY       0x05u
#define PN_DCP_HELLO          0x06u

#define PN_DCP_REQ            0x00u
#define PN_DCP_RESP_SUCCESS   0x01u
#define PN_DCP_RESP_UNSUP     0x05u

#define PN_DCP_OPT_IP         0x01u
#define PN_DCP_OPT_DEV        0x02u
#define PN_DCP_OPT_DHCP       0x03u
#define PN_DCP_OPT_CTRL       0x05u
#define PN_DCP_OPT_ALL        0xFFu
/* Stack Security Class 1 profile (not a PI-assigned option). */
#define PN_DCP_OPT_SEC        0xF0u
#define PN_DCP_SUB_SEC_HMAC   0x01u

#define PN_DCP_SUB_IP_MAC     0x01u
#define PN_DCP_SUB_IP_PARAM   0x02u
#define PN_DCP_SUB_DEV_TYPE   0x01u
#define PN_DCP_SUB_DEV_NAME   0x02u
#define PN_DCP_SUB_DEV_ID     0x03u
#define PN_DCP_SUB_DEV_ROLE   0x04u
#define PN_DCP_SUB_DEV_OPTS      0x05u
#define PN_DCP_SUB_CTRL_SIGNAL   0x03u
#define PN_DCP_SUB_CTRL_RESPONSE 0x04u

/* Identify.res / Get.res / Hello.req value prefix. Not used on Set.res. */
#define PN_DCP_BLOCKINFO_NONE   0x0000u
#define PN_DCP_BLOCKINFO_IP_SET 0x0001u

#define PN_RPC_PORT           34964
#define PN_SNMP_PORT          161

#define PN_BLOCK_IOD_WRITE_REQ 0x0008u
#define PN_BLOCK_IOD_READ_REQ  0x0009u
#define PN_BLOCK_IM0           0x0020u
#define PN_BLOCK_IM1           0x0021u
#define PN_BLOCK_IM2           0x0022u
#define PN_BLOCK_IM3           0x0023u
#define PN_BLOCK_IM4           0x0024u
#define PN_BLOCK_IOD_WRITE_RES 0x8008u
#define PN_BLOCK_IOD_READ_RES  0x8009u
#define PN_BLOCK_AR_REQ        0x0101u
#define PN_BLOCK_IOCR_REQ      0x0102u
#define PN_BLOCK_ALARMCR_REQ   0x0103u
#define PN_BLOCK_EXPSUB_REQ    0x0104u
#define PN_BLOCK_CONTROL_REQ   0x0110u /* IODControlReq PrmEnd (Connect) */
#define PN_BLOCK_APP_READY_REQ 0x0112u /* IOXControlReq ApplicationReady */
#define PN_BLOCK_CONTROL_RES   0x8110u /* IODControlRes PrmEnd Done */
#define PN_BLOCK_APP_READY_RES 0x8112u /* IOXControlRes ApplicationReady Done */
#define PN_BLOCK_AR_RES        0x8101u
#define PN_BLOCK_IOCR_RES      0x8102u
#define PN_BLOCK_ALARMCR_RES   0x8103u
#define PN_BLOCK_SEC_INT       0x0E01u /* stack Security Class 1 integrity block */

#define PN_CONTROL_PRM_END    0x0001u
#define PN_CONTROL_APP_READY  0x0002u
#define PN_CONTROL_DONE       0x0008u

#define PN_INDEX_IM0 0xAFF0u
#define PN_INDEX_IM1 0xAFF1u
#define PN_INDEX_IM2 0xAFF2u
#define PN_INDEX_IM3 0xAFF3u
#define PN_INDEX_IM4 0xAFF4u

#define PN_IOCR_INPUT         0x0001u
#define PN_IOCR_OUTPUT        0x0002u

#define PN_IOPS_GOOD          0x80u
#define PN_DATASTATUS_PRIMARY 0x01u
#define PN_DATASTATUS_VALID   0x04u
#define PN_DATASTATUS_RUN     0x20u

#define PN_STATION_NAME_MAX   240
#define PN_IO_MAX             256
#define PN_FRAME_MAX          1518
#define PN_HMAC_LEN           32
#define PN_PSK_LEN            32
#define PN_UUID_LEN           16

#define PN_CONFORMANCE_CLASS_B  2
#define PN_RT_CLASS_1           1
#define PN_SECURITY_CLASS_1     1

#endif /* PN_TYPES_H */
