#include "ethercat_adapter.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "logger.h"

/*
 * EtherCAT 은 SubDevice(슬레이브) 역할이 이 데몬의 센서 모델에 해당한다.
 * SubDevice 는 ESC ASIC/FPGA 의 on-the-fly 처리가 규격 전제라서, 일반 NIC
 * 만 있는 A-core 타깃에서는 스택을 넣지 않는다 (자체 구현도 SOES 래핑도 아님).
 *
 * 소프트웨어 ESC / Master(SOEM) 를 쓰지 않는 이유는 docs/ethercat.md.
 * ESC 하드웨어가 보드에 올라오면 이 파일을 SOES 번역기로 교체한다.
 */

static int ecat_init(protocol_adapter_t *self, const char *pp, const char *pt)
{
    (void)self;
    (void)pp;
    (void)pt;
    LOG_ERROR("ethercat",
              "EtherCAT SubDevice는 ESC(ASIC 또는 FPGA IP)가 필요합니다. "
              "이 타깃은 일반 NIC만 있어 구현하지 않습니다. "
              "소프트웨어 슬레이브/마스터로 우회하지 않습니다. "
              "docs/ethercat.md 를 보십시오");
    return -ENOTSUP;
}

static int ecat_connect(protocol_adapter_t *self)
{
    (void)self;
    return -ENOTSUP;
}

static void ecat_disconnect(protocol_adapter_t *self) { (void)self; }

static void ecat_poll_cycle(protocol_adapter_t *self) { (void)self; }

static int ecat_read(protocol_adapter_t *self, const char *n, point_value_t *o)
{
    (void)self;
    (void)n;
    (void)o;
    return -ENOTSUP;
}

static int ecat_write(protocol_adapter_t *self, const char *n,
                      const point_value_t *v)
{
    (void)self;
    (void)n;
    (void)v;
    return -ENOTSUP;
}

static int ecat_health(protocol_adapter_t *self, int *c, char *e, size_t elen)
{
    (void)self;
    *c = 0;
    if (elen) {
        snprintf(e, elen, "requires ESC ASIC/FPGA (see docs/ethercat.md)");
    }
    return 0;
}

static void ecat_destroy(protocol_adapter_t *self) { free(self); }

protocol_adapter_t *ethercat_adapter_create(void)
{
    protocol_adapter_t *a = calloc(1, sizeof(protocol_adapter_t));
    if (!a) {
        return NULL;
    }
    a->name = "ethercat";
    a->init = ecat_init;
    a->connect = ecat_connect;
    a->disconnect = ecat_disconnect;
    a->poll_cycle = ecat_poll_cycle;
    a->read_point = ecat_read;
    a->write_point = ecat_write;
    a->health = ecat_health;
    a->destroy = ecat_destroy;
    return a;
}
