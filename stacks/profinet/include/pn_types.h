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
/* Stack-local HMAC profile (not a PI-assigned Security Class 1 option). */
#define PN_DCP_OPT_SEC        0xF0u
#define PN_DCP_SUB_SEC_HMAC   0x01u

#define PN_DCP_SUB_IP_MAC     0x01u
#define PN_DCP_SUB_IP_PARAM   0x02u
#define PN_DCP_SUB_DEV_TYPE   0x01u
#define PN_DCP_SUB_DEV_NAME   0x02u
#define PN_DCP_SUB_DEV_ID     0x03u
#define PN_DCP_SUB_DEV_ROLE   0x04u
#define PN_DCP_SUB_DEV_OPTS   0x05u
#define PN_DCP_SUB_CTRL_RESP  0x04u

#define PN_RPC_PORT           34964
#define PN_SNMP_PORT          161

#define PN_BLOCK_WRITE_REQ    0x0008u
#define PN_BLOCK_READ_REQ     0x0009u
#define PN_BLOCK_WRITE_RES    0x8008u
#define PN_BLOCK_READ_RES     0x8009u
#define PN_BLOCK_AR_REQ       0x0101u
#define PN_BLOCK_IOCR_REQ     0x0102u
#define PN_BLOCK_ALARMCR_REQ  0x0103u
#define PN_BLOCK_EXPSUB_REQ   0x0104u
#define PN_BLOCK_PRMEND_REQ   0x0110u
#define PN_BLOCK_APPRDY_REQ   0x0112u
#define PN_BLOCK_RELEASE_REQ  0x0114u
#define PN_BLOCK_AR_RES       0x8101u
#define PN_BLOCK_IOCR_RES     0x8102u
#define PN_BLOCK_ALARMCR_RES  0x8103u
#define PN_BLOCK_MODDIFF      0x8104u
#define PN_BLOCK_ARSERVER_RES 0x8106u
#define PN_BLOCK_PRMEND_RES   0x8110u
#define PN_BLOCK_APPRDY_RES   0x8112u
#define PN_BLOCK_RELEASE_RES  0x8114u
#define PN_BLOCK_REALIDENT    0x0013u
#define PN_BLOCK_IM0          0x0020u
#define PN_BLOCK_PDPORT_REAL  0x020Fu
#define PN_BLOCK_PDIF_REAL    0x0240u
#define PN_BLOCK_SEC_INT      0x0E01u /* stack-local integrity block */

#define PN_IOCR_INPUT         0x0001u
#define PN_IOCR_OUTPUT        0x0002u

#define PN_CTRL_PRM_END       0x0001u
#define PN_CTRL_APP_RDY       0x0002u
#define PN_CTRL_RELEASE       0x0004u
#define PN_CTRL_DONE          0x0008u

#define PN_CM_OFFLINE         0
#define PN_CM_CONNECTED       1
#define PN_CM_W_APPRDY        2
#define PN_CM_DATAEX          3

#define PN_IOPS_GOOD          0x80u
#define PN_IOPS_BAD           0x00u
#define PN_DATASTATUS_PRIMARY 0x01u
#define PN_DATASTATUS_VALID   0x04u
#define PN_DATASTATUS_RUN     0x20u
#define PN_DATASTATUS_PROBLEM 0x40u

#define PN_INDEX_IM0            0xAFF0u
#define PN_INDEX_REALIDENT_SUB  0x8001u
#define PN_INDEX_PDPORT_REAL    0x802Au
#define PN_INDEX_PDIF_REAL      0x8080u
#define PN_INDEX_REALIDENT_SLOT 0xC001u
#define PN_INDEX_EXPIDENT_AR    0xE000u
#define PN_INDEX_REALIDENT_AR   0xE001u
#define PN_INDEX_WRITE_MULTI    0xE040u
#define PN_INDEX_REALIDENT_API  0xF000u

#define PN_STATION_NAME_MAX   240
#define PN_IO_MAX             256
#define PN_FRAME_MAX          1518
#define PN_HMAC_LEN           32
#define PN_PSK_LEN            32
#define PN_UUID_LEN           16
#define PN_IOCR_MAX           2
#define PN_IOBJ_MAX           8
#define PN_SUBMOD_MAX         16

#define PN_CONFORMANCE_CLASS_B  2
#define PN_RT_CLASS_1           1
#define PN_SECURITY_CLASS_1     1

#endif /* PN_TYPES_H */
