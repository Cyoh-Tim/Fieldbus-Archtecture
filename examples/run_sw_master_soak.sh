#!/usr/bin/env bash
# Software-master soak: in-repo cyclic masters drive real IO against our
# device/server stacks (fake_sensor_app + live TCP loopback).
#
#   examples/run_sw_master_soak.sh                 # all three (MB / SLMP / EIP)
#   examples/run_sw_master_soak.sh modbus
#   examples/run_sw_master_soak.sh slmp --seconds 8
#   examples/run_sw_master_soak.sh ethernetip --eip-mode class1
#   examples/run_sw_master_soak.sh all --seconds 3
#
# Not CODESYS. Not PREEMPT_RT. Not PI / ODVA / Modbus.org / Mitsubishi
# certification. No CAP_NET_RAW. No privileged :502 / :5000 / :44818.
#
# PROFINET is documented-only here: mock / self stub, no fake SoftPLC claim.
# See docs/sw_master_io.md.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

BUILD_DIR=${BUILD_DIR:-"$ROOT/build"}
SKIP_CONFIGURE=0
SKIP_BUILD=0
SECONDS_RUN=4
CYCLES=0
PERIOD_MS=50
EIP_MODE=class1
PROTOCOLS=()
DUT_PID=""

usage() {
    cat <<EOF
usage: $0 [options] [all|modbus|slmp|ethernetip|profinet]...

Starts fake_sensor_app as DUT and runs examples/sw_master.py against it.
Default: all = Modbus TCP + SLMP Binary 3E + EtherNet/IP (sequential).

options:
  --seconds N           master soak wall time per protocol (default 4)
  --cycles N            master poll count (overrides --seconds if >0)
  --period-ms N         cycle period (default 50; not 8ms RT)
  --eip-mode class1|explicit
  --build-dir DIR
  --skip-configure
  --skip-build
  -h, --help

Live loopback ports (do not clash with CTT mock / privileged well-known):
  Modbus TCP     127.0.0.1:15560   config/example.fake_sensor.json
  SLMP Binary 3E 127.0.0.1:15561   config/example.fake_sensor.slmp.json
  EIP TCP/UDP    127.0.0.1:15562 / 15563
                 config/example.sw_master.ethernetip.json  (mock:false)

PROFINET: no live software master. Use examples/run_mock_flow.sh profinet
(in-process CTT mock). This script prints a stub note and skips.

Not certification. Not CODESYS (that path is docs/codesys_master_io.md).
EOF
}

banner() {
    echo "============================================================"
    echo "software master soak — in-repo masters vs our DUT stacks"
    echo "Not CODESYS. Not certification. No PREEMPT_RT. No CAP_NET_RAW."
    echo "============================================================"
}

normalize_proto() {
    case "$1" in
        all) echo all ;;
        modbus|modbus_tcp|mb) echo modbus ;;
        slmp) echo slmp ;;
        ethernetip|eip) echo ethernetip ;;
        profinet|pn) echo profinet ;;
        *) echo "" ;;
    esac
}

config_for() {
    case "$1" in
        modbus) echo "$ROOT/config/example.fake_sensor.json" ;;
        slmp) echo "$ROOT/config/example.fake_sensor.slmp.json" ;;
        ethernetip) echo "$ROOT/config/example.sw_master.ethernetip.json" ;;
        *) echo "" ;;
    esac
}

listen_port_for() {
    case "$1" in
        modbus) echo 15560 ;;
        slmp) echo 15561 ;;
        ethernetip) echo 15562 ;;
        *) echo 0 ;;
    esac
}

title_for() {
    case "$1" in
        modbus) echo "Modbus TCP master (live loopback)" ;;
        slmp) echo "SLMP Binary 3E client (live loopback)" ;;
        ethernetip) echo "EtherNet/IP scanner (live TCP+UDP Class1 / explicit)" ;;
        profinet) echo "PROFINET (no live software master)" ;;
        *) echo "$1" ;;
    esac
}

cleanup_dut() {
    if [ -n "$DUT_PID" ] && kill -0 "$DUT_PID" 2>/dev/null; then
        kill -TERM "$DUT_PID" 2>/dev/null || true
        wait "$DUT_PID" 2>/dev/null || true
    fi
    DUT_PID=""
}
trap cleanup_dut EXIT INT TERM

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-configure) SKIP_CONFIGURE=1 ;;
        --skip-build) SKIP_BUILD=1 ;;
        --seconds)
            if [ $# -lt 2 ]; then
                echo "missing --seconds value" >&2
                exit 1
            fi
            SECONDS_RUN=$2
            shift
            ;;
        --cycles)
            if [ $# -lt 2 ]; then
                echo "missing --cycles value" >&2
                exit 1
            fi
            CYCLES=$2
            shift
            ;;
        --period-ms)
            if [ $# -lt 2 ]; then
                echo "missing --period-ms value" >&2
                exit 1
            fi
            PERIOD_MS=$2
            shift
            ;;
        --eip-mode)
            if [ $# -lt 2 ]; then
                echo "missing --eip-mode value" >&2
                exit 1
            fi
            EIP_MODE=$2
            shift
            ;;
        --build-dir)
            if [ $# -lt 2 ]; then
                echo "missing --build-dir value" >&2
                exit 1
            fi
            BUILD_DIR=$2
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --*)
            echo "unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
        *)
            n=$(normalize_proto "$1")
            if [ -z "$n" ]; then
                echo "unknown protocol: $1" >&2
                usage >&2
                exit 1
            fi
            PROTOCOLS+=("$n")
            ;;
    esac
    shift
done

if [ ${#PROTOCOLS[@]} -eq 0 ]; then
    PROTOCOLS=(all)
fi

expanded=()
for p in "${PROTOCOLS[@]}"; do
    if [ "$p" = "all" ]; then
        expanded+=(modbus slmp ethernetip)
    else
        expanded+=("$p")
    fi
done
PROTOCOLS=("${expanded[@]}")

banner
echo "root=$ROOT"
echo "build_dir=$BUILD_DIR"
echo "protocols=${PROTOCOLS[*]}"
echo "seconds=$SECONDS_RUN cycles=$CYCLES period_ms=$PERIOD_MS eip_mode=$EIP_MODE"
echo

if [ "$SKIP_CONFIGURE" -eq 0 ]; then
    cmake -S "$ROOT" -B "$BUILD_DIR" \
        -DBUILD_DAEMON=ON \
        -DBUILD_API=ON \
        -DBUILD_CTT=OFF
fi

if [ "$SKIP_BUILD" -eq 0 ]; then
    cmake --build "$BUILD_DIR" --target fake_sensor_app
fi

APP="$BUILD_DIR/fake_sensor_app"
MASTER="$ROOT/examples/sw_master.py"
if [ ! -x "$APP" ]; then
    echo "fake_sensor_app not found at $APP (need BUILD_DAEMON=ON BUILD_API=ON)" >&2
    exit 1
fi
if [ ! -f "$MASTER" ]; then
    echo "missing $MASTER" >&2
    exit 1
fi

dut_lifetime() {
    local extra=12
    if [ "$CYCLES" -gt 0 ]; then
        echo $((CYCLES * 2 + extra))
    else
        echo $((SECONDS_RUN + extra))
    fi
}

run_profinet_stub() {
    echo "=== PROFINET: not on the software-master live path ==="
    echo "No fake SoftPLC / PN Controller is started here."
    echo "Live RT Class 1 needs a real NIC (often CAP_NET_RAW) — lab only."
    echo "Equipment-free path is in-process mock:"
    echo "  ./examples/run_mock_flow.sh profinet"
    echo "  config/example.fake_sensor.profinet.json  (iface=mock)"
    echo "IRT / CC-C are permanent non-goals. Not PI certification."
    echo "PN stub note OK (skipped live master)"
}

run_one() {
    local proto="$1"
    local cfg port title life
    title=$(title_for "$proto")
    echo
    echo "=== $title ==="

    if [ "$proto" = "profinet" ]; then
        run_profinet_stub
        return 0
    fi

    cfg=$(config_for "$proto")
    port=$(listen_port_for "$proto")
    if [ ! -f "$cfg" ]; then
        echo "config not found: $cfg" >&2
        return 1
    fi
    life=$(dut_lifetime)
    echo "config=$cfg listen=127.0.0.1:$port dut_seconds=$life"
    echo "transport=live_tcp_loopback (EIP also UDP Class1 when eip_mode=class1)"

    cleanup_dut
    "$APP" --seconds "$life" "$cfg" &
    DUT_PID=$!
    sleep 0.4
    if ! kill -0 "$DUT_PID" 2>/dev/null; then
        wait "$DUT_PID" || true
        echo "DUT exited early ($proto)" >&2
        DUT_PID=""
        return 1
    fi

    local st_args=(python3 "$MASTER" --protocol "$proto" --host 127.0.0.1 --period-ms "$PERIOD_MS")
    if [ "$CYCLES" -gt 0 ]; then
        st_args+=(--cycles "$CYCLES")
    else
        st_args+=(--seconds "$SECONDS_RUN")
    fi
    if [ "$proto" = "ethernetip" ]; then
        st_args+=(--eip-mode "$EIP_MODE" --eip-port 15562 --eip-udp-port 15563)
    fi

    local rc=0
    "${st_args[@]}" || rc=$?
    cleanup_dut
    if [ "$rc" -ne 0 ]; then
        echo "$proto FAIL rc=$rc" >&2
        return "$rc"
    fi
    echo "$proto PASS"
    return 0
}

fail=0
for p in "${PROTOCOLS[@]}"; do
    if ! run_one "$p"; then
        fail=1
        break
    fi
done

echo
if [ "$fail" -ne 0 ]; then
    echo "software master soak FAILED (not a certification result)" >&2
    exit 1
fi
echo "software master soak PASS (internal; not PI/ODVA/Modbus.org/Mitsubishi/CODESYS)"
exit 0
