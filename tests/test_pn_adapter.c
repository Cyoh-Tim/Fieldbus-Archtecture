#include "profinet_adapter.h"

#include <stdio.h>
#include <string.h>

static int g_fail;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

int main(void)
{
    protocol_adapter_t *a = profinet_adapter_create();
    expect(a != NULL, "adapter create");
    if (!a) {
        return 1;
    }

    const char *params =
        "{\"iface\":\"mock\",\"device_name\":\"sensor-line1\","
        "\"vendor_id\":43981,\"device_id\":1,\"security_class\":0,"
        "\"input_len\":32,\"output_len\":8,\"cycle_us\":8000}";
    const char *points =
        "[{\"name\":\"s1_in\",\"access\":\"read\",\"length\":4,"
        "\"address\":{\"profinet\":{\"slot\":1,\"subslot\":1,"
        "\"byte_offset\":0,\"length\":4}}},"
        "{\"name\":\"s2_in\",\"access\":\"read\",\"length\":4,"
        "\"address\":{\"profinet\":{\"slot\":2,\"subslot\":1,"
        "\"byte_offset\":0,\"length\":4}}},"
        "{\"name\":\"trig\",\"access\":\"write\",\"length\":1,"
        "\"address\":{\"profinet\":{\"slot\":1,\"subslot\":1,"
        "\"byte_offset\":0,\"length\":1}}}]";

    expect(a->init(a, params, points) == 0, "init two-slot points");
    expect(a->connect(a) == 0, "stack start");

    uint8_t s1[4] = {1, 2, 3, 4};
    uint8_t s2[4] = {9, 8, 7, 6};
    point_value_t w = {.data = s1, .len = 4};
    expect(a->write_point(a, "s1_in", &w) == 0, "write slot 1");
    w.data = s2;
    expect(a->write_point(a, "s2_in", &w) == 0, "write slot 2 at stride 32");

    uint8_t buf[4];
    point_value_t r = {.data = buf, .len = 4};
    memset(buf, 0, sizeof(buf));
    expect(a->read_point(a, "s1_in", &r) == 0 && memcmp(buf, s1, 4) == 0,
           "read slot 1");
    memset(buf, 0, sizeof(buf));
    expect(a->read_point(a, "s2_in", &r) == 0 && memcmp(buf, s2, 4) == 0,
           "read slot 2 does not collide with slot 1");

    a->disconnect(a);
    a->destroy(a);

    if (g_fail) {
        fprintf(stderr, "pn adapter tests FAILED\n");
        return 1;
    }
    fprintf(stderr, "pn adapter tests OK\n");
    return 0;
}
