#include "cclink_adapter.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "logger.h"

/*
 * CC-Link 스택/사양이 확정되면 modbus_adapter.c 또는 profinet_adapter.c 를
 * 템플릿 삼아 여기에 구현한다. protocol_params.station_no 등은 이미
 * docs/design.md 3.3 절에 예시가 정의되어 있으므로 그 구조를 따를 것.
 */

static int stub_init(protocol_adapter_t *self, const char *pp, const char *pt)
{
    (void)self; (void)pp; (void)pt;
    LOG_ERROR("cclink", "CC-Link 어댑터는 아직 구현되지 않았습니다");
    return -ENOSYS;
}
static int stub_connect(protocol_adapter_t *self) { (void)self; return -ENOSYS; }
static void stub_disconnect(protocol_adapter_t *self) { (void)self; }
static void stub_poll_cycle(protocol_adapter_t *self) { (void)self; }
static int stub_read(protocol_adapter_t *self, const char *n, point_value_t *o)
{ (void)self; (void)n; (void)o; return -ENOSYS; }
static int stub_write(protocol_adapter_t *self, const char *n, const point_value_t *v)
{ (void)self; (void)n; (void)v; return -ENOSYS; }
static int stub_health(protocol_adapter_t *self, int *c, char *e, size_t elen)
{
    (void)self;
    *c = 0;
    if (elen) snprintf(e, elen, "not implemented");
    return 0;
}
static void stub_destroy(protocol_adapter_t *self) { free(self); }

protocol_adapter_t *cclink_adapter_create(void)
{
    protocol_adapter_t *a = calloc(1, sizeof(protocol_adapter_t));
    if (!a) return NULL;
    a->name = "cclink";
    a->init = stub_init;
    a->connect = stub_connect;
    a->disconnect = stub_disconnect;
    a->poll_cycle = stub_poll_cycle;
    a->read_point = stub_read;
    a->write_point = stub_write;
    a->health = stub_health;
    a->destroy = stub_destroy;
    return a;
}
