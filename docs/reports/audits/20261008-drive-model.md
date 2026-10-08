# 감사 2026-10-08 — 구동 모델 (Modbus/SLMP 사이클 기반 지양)

- 영역: 코어 사이클 루프 + Modbus·SLMP 서버/클라이언트 구동
- 출처: 저장소 담당자 지시 (2026-10-08). 설계 원칙은 [`docs/design.md`](../../design.md) 1장 5항.
- 기준 커밋: `2a211d1` (main)
- 큐 추가: 3개 (A20261008-1 → 큐 20, -2 → 21, -3 → 22). 담당자 결정으로 기존 20 번 앞에 넣었다. -2, -3 은 -1 이후.
- 판정 근거: Modbus Application Protocol V1.1b3 / Messaging on TCP/IP Implementation Guide V1.0b
  (요청-응답, 주기 없음), MELSEC SLMP Reference Manual (요청-응답, 3E), pymodbus 3.15.0 / pymcprotocol 0.3.0 으로 잰
  응답 시간. 기대값은 스택 코드에서 만들지 않았다.
- 참고 구현: 같은 설계를 libmodbus 기반 별도 데몬(fieldbusd)에 먼저 구현해 검증했다
  (단위·종단 테스트, ASan/UBSan/TSan). 이 보고서의 참고 diff 는 그 구현을 이 저장소 `core/fb_api.c` 에 맞춘 것이다.

## 배경 — 왜 결함으로 보나

Modbus 와 SLMP 는 **요청-응답형**이다. 프로토콜에 사이클이 없고, 통신 시점은 마스터가 정한다.
그런데 코어는 모든 어댑터의 `poll_cycle` 을 `cycle_ms`(기본 8ms) 고정 주기로만 부른다. 그 결과

1. 서버(슬레이브)는 요청이 와도 다음 사이클까지 응답하지 않는다. 지연이 최대 `cycle_ms` 다.
   `cycle_ms` 를 늘리면 응답 지연이 그대로 늘어난다 (아래 재현: `cycle_ms=1000` 에서 863ms).
2. 요청이 없어도 8ms 마다 깨어나 CPU 를 쓴다.
3. 클라이언트(마스터)의 읽기 폴링 주기가 `cycle_ms` 에 묶여, 현장이 요구하는 갱신 주기와 따로 정할 수 없다.

고정 사이클은 주기 I/O 가 프로토콜 자체인 PROFINET RT·EtherNet/IP Class 1 에만 맞다.

## A20261008-1. 코어가 이벤트 구동을 지원하지 않는다 (`wait_fds`)

**문제:** `run_cycle_loop` 는 `poll_cycle` 호출 뒤 항상 `clock_nanosleep` 으로 다음 `cycle_ms` 까지 잔다.
어댑터가 "소켓에 데이터가 오면 깨워 달라" 고 알릴 방법이 인터페이스에 없다.
또 `thread_stop` 이 `volatile int` 라서 사이클 스레드가 락 없이 읽는 것이 데이터 레이스다 (ThreadSanitizer 경고).

**근거 (파일:줄, 기준 커밋 `2a211d1`):**
- `include/protocol_adapter.h:40-41` — `poll_cycle` 만 있고 대기 fd 를 알리는 함수가 없다.
- `core/fb_api.c:739-784` `run_cycle_loop` — 고정 주기 `clock_nanosleep` 만 있다.
- `core/fb_api.c:65` — `volatile int thread_stop;` (`fb_stop`/`fb_close` 가 쓰고 사이클 스레드가 락 없이 읽음).

**재현:** 인터페이스 부재라 단독 재현은 없다. 효과는 A20261008-2·-3 의 오라클로 드러난다.
TSan: `fieldbusd` 의 같은 코어로 `test_fb_api` 를 `-fsanitize=thread` 로 돌리면
`stop_thread_unlocked_prep` 쓰기 ↔ `run_cycle_loop` 읽기 데이터 레이스가 보고된다.

**기대값과 출처:** `docs/design.md` 1장 5항. 인터페이스는 아래 참고 diff 의 `wait_fds` 그대로.

- 어댑터가 `wait_fds` 를 구현하고 0 이상을 반환하면, 코어는 그 fd + 내부 깨우기 파이프를 `poll()` 로 기다렸다가
  이벤트가 오거나 `*timeout_ms` 가 지나면 `poll_cycle` 을 부른다.
- `wait_fds` 가 NULL 이거나 음수를 반환하면 지금과 똑같이 `cycle_ms` 고정 주기다 (EIP/PN/CC-Link 는 바뀌지 않는다).
- `fb_stop`/`fb_close` 는 대기 중인 스레드를 깨워 즉시 끝낸다. `fb_run(stop_flag)` 는 이벤트 모드에서도
  `stop_flag` 를 100ms 안에 본다 (`core/main.c` 는 시그널 핸들러가 `g_stop` 만 세운다).
- `fb_poll()` (앱이 한 단계씩 돌리는 임베디드 모드) 은 바뀌지 않는다.
- `epoll` 이 아니라 `poll()` 로 한다 (프로세스당 프로토콜 하나라 fd 가 적다. 설계 문서 근거).

**반드시 지킬 것 — reload 와 `poll()` 경합:** 사이클 스레드가 옛 어댑터의 listen fd 로 `poll()` 중일 때
`fb_reload` 가 그 fd 를 close 하면, 커널은 `poll()` 이 끝날 때까지 소켓을 놓지 않는다. 그래서 같은 포트로 새 어댑터가
bind 하면 `EADDRINUSE` 로 reload 가 실패한다 (참고 구현에서 실제로 겪음). `fb_reload` 는 락을 잡은 뒤
**사이클 스레드를 `poll()` 에서 빼내고 다시 들어가지 못하게** 한 다음(참고 diff 의 `quiesce_locked`) disconnect·connect 하고,
끝나면 풀어 준다(`resume_locked`).

**수정 범위:** `include/protocol_adapter.h`, `core/`, `tests/` (테스트 타깃 추가는 `CMakeLists.txt`).
어댑터는 바꾸지 않는다 (다음 두 항목).

**완료 조건:**
- 새 단위 테스트 (가짜 어댑터로, 프로토콜 무관):
  1. `wait_fds` 가 파이프 읽기 fd 를 주는 가짜 어댑터 + `cycle_ms=1000` + `fb_start`: 파이프에 1바이트 쓴 뒤 100ms 안에
     `poll_cycle` 이 불린다.
  2. 같은 상태에서 이벤트가 없으면 1초 동안 `poll_cycle` 호출이 `*timeout_ms` 로 정한 횟수 이하다 (예: timeout -1 이면 0회).
  3. 대기 중 `fb_stop` 이 200ms 안에 끝난다.
  4. `connect` 에서 TCP 포트를 listen 하고 그 fd 를 `wait_fds` 로 주는 가짜 어댑터로 `fb_start` 후 **같은 설정으로
     `fb_reload`** 가 성공한다 (`EADDRINUSE` 회귀 방지).
  5. `wait_fds` 가 NULL 인 가짜 어댑터는 지금처럼 `cycle_ms` 주기로 불린다.
- 기존 단위 테스트·CTT·오라클 결과가 그대로다 (어댑터가 아직 `wait_fds` 를 구현하지 않으므로 오라클 판정 변화 없음).
- 새 테스트를 `-fsanitize=thread` 빌드로 돌린 결과(경고 없음)를 PR 설명에 붙인다.
- 스크래치 검증 (`2a211d1` 기준): 아래 참고 diff 를 적용하고 `BUILD_DAEMON=ON BUILD_CTT=ON` 단위 테스트
  `ctest -LE soak_ci` 95/95 통과.

<details><summary>참고 diff — <code>include/protocol_adapter.h</code></summary>

```diff
--- a/include/protocol_adapter.h
+++ b/include/protocol_adapter.h
@@ -1,6 +1,7 @@
 #ifndef PROTOCOL_ADAPTER_H
 #define PROTOCOL_ADAPTER_H
 
+#include <poll.h>
 #include <stddef.h>
 #include <stdint.h>
 
@@ -37,9 +38,23 @@
     int (*connect)(protocol_adapter_t *self);
     void (*disconnect)(protocol_adapter_t *self);
 
-    /* 스케줄러가 cycle_ms 주기로 호출. 어댑터 내부에서 폴링/송수신 수행 */
+    /* 어댑터 내부 폴링/송수신. 호출 시점은 아래 wait_fds 구현 여부로 정해진다. */
     void (*poll_cycle)(protocol_adapter_t *self);
 
+    /*
+     * (선택) 이벤트 구동. 요청-응답형 프로토콜(Modbus 서버 등)은 주기가 없으므로
+     * 고정 cycle_ms 로 깨어날 필요 없이, 소켓에 데이터가 올 때 바로 처리한다.
+     *
+     * 어댑터가 기다릴 fd 를 fds[0..cap) 에 채우고 개수를 반환한다. *timeout_ms 에는
+     * fd 이벤트가 없어도 poll_cycle 을 불러야 하는 시간(ms, 유휴 연결 정리 등)을,
+     * 필요 없으면 -1 을 넣는다. 코어는 poll() 이 깨면 poll_cycle 을 호출한다.
+     *
+     * NULL 이거나 음수를 반환하면 코어는 cycle_ms 고정 주기로 poll_cycle 을 부른다
+     * (EtherNet/IP·PROFINET 의 주기 I/O, Modbus 클라이언트의 폴링 등).
+     */
+    int (*wait_fds)(protocol_adapter_t *self, struct pollfd *fds, int cap,
+                    int *timeout_ms);
+
     int (*read_point)(protocol_adapter_t *self, const char *point_name,
                        point_value_t *out);
```

</details>

<details><summary>참고 diff — <code>core/fb_api.c</code> (깨우기 파이프, 이벤트 대기, reload quiesce, atomic thread_stop)</summary>

```diff
--- a/core/fb_api.c
+++ b/core/fb_api.c
@@ -1,14 +1,16 @@
-#define _POSIX_C_SOURCE 200809L
+#define _GNU_SOURCE
 
 #include "fb_api.h"
 
 #include <errno.h>
+#include <fcntl.h>
 #include <math.h>
 #include <pthread.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <time.h>
+#include <unistd.h>
 
 #include <cJSON.h>
 
@@ -20,6 +22,9 @@
 #define FB_MAX_POINTS 256
 #define FB_WIRE_CAP 1024
 #define FB_PATH_MAX 4096
+#define FB_WAIT_FDS_MAX 32
+/* fb_run(stop_flag) 이벤트 모드에서 stop_flag 를 확인하는 최대 간격 */
+#define FB_RUN_STOP_CHECK_MS 100
 
 typedef enum {
     FB_KIND_BOOL = 0,
@@ -62,7 +67,13 @@
     int have_session;
     int thread_on;
     pthread_t thread;
-    volatile int thread_stop;
+    _Atomic int thread_stop; /* 사이클 스레드가 락 없이 읽음 */
+    int wake_fd[2]; /* 이벤트 대기 중인 사이클 스레드 깨우기 (stop/reload) */
+    /* reload 동안 사이클 스레드를 poll() 밖에 붙잡아 둔다. poll() 중인 fd 는
+     * close 해도 커널이 소켓을 놓지 않아 같은 포트 재bind 가 실패하기 때문. */
+    pthread_cond_t cv;
+    int in_wait; /* 사이클 스레드가 어댑터 fd 로 poll() 중 */
+    int paused;  /* reload 진행 중 — 새 대기 진입 금지 */
     char last_error[FB_ERROR_MSG_MAX];
     char config_path[FB_PATH_MAX];
 };
@@ -736,6 +748,98 @@
     return FB_OK;
 }
 
+static void wake_cycle_thread(fb_runtime_t *rt)
+{
+    if (rt->wake_fd[1] >= 0) {
+        char c = 1;
+        (void)!write(rt->wake_fd[1], &c, 1);
+    }
+}
+
+static void drain_wake(fb_runtime_t *rt)
+{
+    char buf[64];
+    while (read(rt->wake_fd[0], buf, sizeof(buf)) > 0) {
+    }
+}
+
+/*
+ * 이벤트 모드 한 번: 어댑터가 준 fd + 깨우기 파이프를 poll() 로 기다렸다가
+ * poll_cycle 을 부른다. 어댑터가 이벤트 모드를 쓰지 않으면 1 을 반환해
+ * 호출자가 고정 주기 모드로 처리하게 한다.
+ */
+static int event_step(fb_runtime_t *rt, volatile int *stop_flag)
+{
+    struct pollfd fds[1 + FB_WAIT_FDS_MAX];
+    int timeout_ms = -1;
+    int nfd = -1;
+    pthread_mutex_lock(&rt->mu);
+    while (rt->paused && !rt->thread_stop) {
+        pthread_cond_wait(&rt->cv, &rt->mu);
+    }
+    protocol_adapter_t *a = rt->session.adapter;
+    if (a && a->wait_fds) {
+        nfd = a->wait_fds(a, fds + 1, FB_WAIT_FDS_MAX, &timeout_ms);
+    }
+    if (nfd >= 0) {
+        rt->in_wait = 1;
+    }
+    pthread_mutex_unlock(&rt->mu);
+    if (nfd < 0) {
+        return 1;
+    }
+    if (nfd > FB_WAIT_FDS_MAX) {
+        nfd = FB_WAIT_FDS_MAX;
+    }
+    fds[0].fd = rt->wake_fd[0];
+    fds[0].events = POLLIN;
+    fds[0].revents = 0;
+    if (stop_flag &&
+        (timeout_ms < 0 || timeout_ms > FB_RUN_STOP_CHECK_MS)) {
+        timeout_ms = FB_RUN_STOP_CHECK_MS;
+    }
+    int rc = poll(fds, (nfds_t)(nfd + 1), timeout_ms);
+    int perr = errno;
+    pthread_mutex_lock(&rt->mu);
+    rt->in_wait = 0;
+    pthread_cond_broadcast(&rt->cv);
+    pthread_mutex_unlock(&rt->mu);
+    if (rc < 0 && perr != EINTR) {
+        errno = perr;
+        LOG_ERROR("fb_api", "poll 실패: %s", strerror(errno));
+        struct timespec ts = {0, 10 * 1000000L};
+        nanosleep(&ts, NULL);
+        return 0;
+    }
+    if (fds[0].revents) {
+        drain_wake(rt);
+    }
+    if ((stop_flag && *stop_flag) || rt->thread_stop) {
+        return 0;
+    }
+    pthread_mutex_lock(&rt->mu);
+    int prc = poll_locked(rt);
+    pthread_mutex_unlock(&rt->mu);
+    return prc == FB_OK ? 0 : prc;
+}
+
+/* rt->mu 를 잡은 상태에서 호출. 사이클 스레드가 poll() 에서 나올 때까지 기다리고
+ * 다시 들어가지 못하게 한다. */
+static void quiesce_locked(fb_runtime_t *rt)
+{
+    rt->paused = 1;
+    while (rt->in_wait) {
+        wake_cycle_thread(rt);
+        pthread_cond_wait(&rt->cv, &rt->mu);
+    }
+}
+
+static void resume_locked(fb_runtime_t *rt)
+{
+    rt->paused = 0;
+    pthread_cond_broadcast(&rt->cv);
+}
+
 static int run_cycle_loop(fb_runtime_t *rt, volatile int *stop_flag)
 {
     struct timespec next;
@@ -744,6 +848,17 @@
         if ((stop_flag && *stop_flag) || rt->thread_stop) {
             break;
         }
+        /* 요청-응답형 어댑터: 주기 없이 소켓 이벤트로 구동 */
+        int erc = event_step(rt, stop_flag);
+        if (erc == 0) {
+            clock_gettime(CLOCK_MONOTONIC, &next); /* 주기 모드 전환 대비 */
+            continue;
+        }
+        if (erc < 0) {
+            return erc;
+        }
+
+        /* 주기형 어댑터 (EtherNet/IP, PROFINET 의 cyclic I/O, 클라이언트 폴링) */
         int cycle_ms;
         struct timespec before;
         clock_gettime(CLOCK_MONOTONIC, &before);
@@ -796,6 +911,7 @@
         return 0;
     }
     rt->thread_stop = 1;
+    wake_cycle_thread(rt);
     return 1;
 }
 
@@ -866,20 +982,37 @@
         free(rt);
         return FB_ERR_NOMEM;
     }
+    if (pthread_cond_init(&rt->cv, NULL) != 0) {
+        pthread_mutex_destroy(&rt->mu);
+        free(rt);
+        return FB_ERR_NOMEM;
+    }
+    if (pipe2(rt->wake_fd, O_NONBLOCK | O_CLOEXEC) != 0) {
+        pthread_cond_destroy(&rt->cv);
+        pthread_mutex_destroy(&rt->mu);
+        free(rt);
+        return FB_ERR_NOMEM;
+    }
     snprintf(rt->config_path, sizeof(rt->config_path), "%s", config_path);
 
     fb_session_t sess;
     int rc = session_build(config_path, &sess, rt->last_error,
                            sizeof(rt->last_error));
     if (rc != FB_OK) {
+        pthread_cond_destroy(&rt->cv);
         pthread_mutex_destroy(&rt->mu);
+        close(rt->wake_fd[0]);
+        close(rt->wake_fd[1]);
         free(rt);
         return rc;
     }
     rc = session_connect(&sess, rt->last_error, sizeof(rt->last_error));
     if (rc != FB_OK) {
         session_teardown(&sess, 0);
+        pthread_cond_destroy(&rt->cv);
         pthread_mutex_destroy(&rt->mu);
+        close(rt->wake_fd[0]);
+        close(rt->wake_fd[1]);
         free(rt);
         return rc;
     }
@@ -900,6 +1033,7 @@
         return FB_OK;
     }
     rt->thread_stop = 1;
+    wake_cycle_thread(rt);
     if (rt->thread_on) {
         pthread_join(rt->thread, NULL);
         rt->thread_on = 0;
@@ -910,7 +1044,10 @@
         rt->have_session = 0;
     }
     pthread_mutex_unlock(&rt->mu);
+    pthread_cond_destroy(&rt->cv);
     pthread_mutex_destroy(&rt->mu);
+    close(rt->wake_fd[0]);
+    close(rt->wake_fd[1]);
     free(rt);
     return FB_OK;
 }
@@ -943,6 +1080,7 @@
         session_teardown(&neu, 0);
         return FB_ERR_STATE;
     }
+    quiesce_locked(rt);
 
     if (rt->session.adapter->disconnect) {
         rt->session.adapter->disconnect(rt->session.adapter);
@@ -953,6 +1091,7 @@
         rec_err[0] = '\0';
         int rec = session_connect(&rt->session, rec_err, sizeof(rec_err));
         rt_set_err(rt, err[0] ? err : "reload connect failed");
+        resume_locked(rt);
         pthread_mutex_unlock(&rt->mu);
         session_teardown(&neu, 0);
         LOG_ERROR("fb_api",
@@ -966,6 +1105,7 @@
     rt->generation++;
     snprintf(rt->config_path, sizeof(rt->config_path), "%s", config_path);
     rt->last_error[0] = '\0';
+    resume_locked(rt); /* 사이클 스레드는 새 어댑터의 fd 로 다시 대기 */
     pthread_mutex_unlock(&rt->mu);
 
     session_teardown(&old, 0);
```

</details>

## A20261008-2. Modbus 서버가 사이클마다만 요청을 처리하고, 클라이언트 폴링 주기가 `cycle_ms` 에 묶여 있다

**문제:**
- 서버: `mb_stack_poll` 이 `poll_cycle` 안에서만 accept·요청 처리를 하므로, 응답이 최대 `cycle_ms` 늦다.
- 클라이언트: `mb_poll_cycle` 이 매 사이클 모든 포인트를 읽는다. 읽기 주기를 따로 정할 수 없다.
  (쓰기는 이미 `mb_write_point` 에서 즉시 전송한다 — 바꾸지 않는다.)

**근거 (파일:줄, 기준 커밋 `2a211d1`):**
- `stacks/modbus/src/mb_stack.c:1133-1165` `mb_stack_poll` — 서버 처리가 poll 호출 시점에만 일어남.
- `adapters/modbus/modbus_adapter.c:562-582` `mb_poll_cycle` — 클라이언트는 매 호출마다 전 포인트 `mb_stack_client_read`.

**재현 (오라클, 수정 전):** `cycle_ms=1000` 서버 어댑터에 pymodbus 가 5번 읽고 왕복 시간을 잰다.

```
ORACLE_BUILD_DIR=build-oracle python -m pytest tests/oracle/test_modbus_oracle.py \
  -k test_server_response_does_not_wait_for_cycle --runxfail --tb=line
test_modbus_oracle.py:820: AssertionError: cycle_ms=1000 에서 최대 응답 863 ms
```

**기대값과 출처:** Modbus Messaging on TCP/IP Implementation Guide — 서버는 요청을 받으면 응답한다 (주기 개념 없음).
루프백 왕복은 1ms 미만이므로 오라클 상한 100ms 는 여유 있는 기준이다 (`cycle_ms=5` 로 같은 테스트를 돌리면 통과함을 확인).

**수정 범위:** `stacks/modbus/`, `adapters/modbus/`, `tests/`, `docs/modbus_stack.md`. A20261008-1 이후.
- 서버: 스택에 대기 fd 목록 함수(listen fd + 접속한 마스터 fd)를 추가하고, 어댑터 `wait_fds` 로 넘긴다.
  `*timeout_ms` 는 가장 이른 유휴 타임아웃(`idle_timeout_ms`)까지 남은 시간, 마스터가 없으면 -1.
- 클라이언트: `protocol_params.poll_interval_ms` (선택) 를 추가한다.
  - 설정하면: `wait_fds` 가 fd 0개 + `*timeout_ms` = 다음 읽기까지 남은 시간을 반환하고, `poll_cycle` 은 그 시각이 됐을
    때만 전 포인트를 읽는다 (재연결 백오프도 같은 타이머로).
  - 설정하지 않으면: `wait_fds` 가 -1 → 지금처럼 `cycle_ms` 마다 (기존 설정 호환).
- `docs/modbus_stack.md` 7절 표에 `poll_interval_ms` 를 추가하고, 서버는 `cycle_ms` 를 쓰지 않는다고 적는다.

**완료 조건:**
- 오라클 `test_modbus_oracle.py::test_server_response_does_not_wait_for_cycle` 이 통과하고
  `@known_defect("A20261008-2", …)` 표시를 지운다.
- 같은 파일의 다른 결과가 그대로다.
- 단위 테스트: 클라이언트 `poll_interval_ms=50`, `cycle_ms=1000`, `fb_start` 상태에서 가짜 서버가 1초 동안 받은
  읽기 요청 수가 포인트 수 × 약 20회 (±50%) 이고, `poll_interval_ms` 가 없으면 지금과 같다.
- 스크래치 검증 (`2a211d1` + A20261008-1 참고 diff): 서버 `wait_fds` 최소 구현(listen + 마스터 fd, timeout 1000/-1)만
  넣었을 때 이 오라클이 XPASS(strict) 였고, 표시를 지우면 Modbus·SLMP 오라클이 30 passed / 24 xfailed 로 다른 판정 변화가 없었다.

## A20261008-3. SLMP 서버(시뮬)가 사이클마다만 요청을 처리하고, 클라이언트 폴링 주기가 `cycle_ms` 에 묶여 있다

**문제:** A20261008-2 와 같다.
- 서버(시뮬): `slmp_stack_poll` 이 `poll_cycle` 안에서만 accept·요청 처리.
- 클라이언트: `slmp_poll_cycle` 이 매 사이클 PLC→센서(`access: write`) 포인트를 batch read.
  (센서→PLC 쓰기는 이미 `slmp_write_point` 에서 즉시 `remote_sync_write` — 바꾸지 않는다.)

**근거 (파일:줄, 기준 커밋 `2a211d1`):**
- `stacks/slmp/src/slmp_stack.c:1341-1362` `slmp_stack_poll`.
- `adapters/slmp/slmp_adapter.c:699-722` `slmp_poll_cycle`.

**재현 (오라클, 수정 전):** `cycle_ms=1000` 서버 어댑터에 pymcprotocol 이 D400 을 5번 읽는다.

```
ORACLE_BUILD_DIR=build-oracle python -m pytest tests/oracle/test_slmp_oracle.py \
  -k test_server_response_does_not_wait_for_cycle --runxfail --tb=line
test_slmp_oracle.py:337: AssertionError: cycle_ms=1000 에서 최대 응답 863 ms
```

**기대값과 출처:** SLMP 는 요청 메시지에 응답 메시지로 답하는 방식이다 (MELSEC SLMP Reference Manual, 3E 프레임).
상한 100ms 는 Modbus 와 같은 기준.

**수정 범위:** `stacks/slmp/`, `adapters/slmp/`, `tests/`, `docs/slmp_stack.md`. A20261008-1 이후.
A20261008-2 와 같은 방식 (서버 `wait_fds`, 클라이언트 `protocol_params.poll_interval_ms` 선택, 없으면 기존 동작).
`docs/slmp_stack.md` 6.1절 `protocol_params` 와 8절 런타임 흐름을 고친다.

**완료 조건:**
- 오라클 `test_slmp_oracle.py::test_server_response_does_not_wait_for_cycle` 이 통과하고
  `@known_defect("A20261008-3", …)` 표시를 지운다. 같은 파일의 다른 결과가 그대로다.
- 단위 테스트: A20261008-2 와 같은 클라이언트 `poll_interval_ms` 테스트 (가짜 3E PLC).
- 스크래치 검증: A20261008-2 와 같이 확인함 (서버 최소 `wait_fds` 로 XPASS).

## 확인 필요 (큐에 넣지 않음)

- 클라이언트 트랜잭션은 여전히 `poll_cycle` 안에서 동기(응답 대기)다. 응답 타임아웃 동안 같은 스레드의 앱 요청이
  기다린다. 비동기 트랜잭션으로 바꿀지는 별도 판단.
- libmodbus 기반 참고 구현에서는 "지원하지 않는 FC 에 대한 응답 후 sleep+flush" 문제가 있었으나, 이 저장소 자체 스택은
  예외 응답만 보내므로 해당 없음.
