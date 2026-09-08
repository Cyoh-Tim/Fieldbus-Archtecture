#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "ethercat_adapter.h"

/*
 * EtherCAT 어댑터는 ESC 하드웨어가 없는 한 통신 스택을 올리지 않는다.
 * protocol 키가 레지스트리에 있더라도 init 이 -ENOTSUP 이어야 한다.
 */
int main(void)
{
    protocol_adapter_t *a = ethercat_adapter_create();
    if (!a) {
        fprintf(stderr, "ethercat_adapter_create 실패\n");
        return 1;
    }
    if (strcmp(a->name, "ethercat") != 0) {
        fprintf(stderr, "name 불일치: %s\n", a->name);
        a->destroy(a);
        return 1;
    }

    int rc = a->init(a, "{}", "[]");
    if (rc != -ENOTSUP) {
        fprintf(stderr, "init 이 -ENOTSUP 가 아님: %d\n", rc);
        a->destroy(a);
        return 1;
    }

    if (a->connect(a) != -ENOTSUP) {
        fprintf(stderr, "connect 이 -ENOTSUP 가 아님\n");
        a->destroy(a);
        return 1;
    }

    int connected = 1;
    char err[128];
    err[0] = '\0';
    if (a->health(a, &connected, err, sizeof(err)) != 0 || connected != 0) {
        fprintf(stderr, "health 기대값 불일치 connected=%d\n", connected);
        a->destroy(a);
        return 1;
    }
    if (strstr(err, "ESC") == NULL) {
        fprintf(stderr, "health 메시지에 ESC 안내가 없음: %s\n", err);
        a->destroy(a);
        return 1;
    }

    a->destroy(a);
    return 0;
}
