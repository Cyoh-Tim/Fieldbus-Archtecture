#!/usr/bin/env bash
# Equipment-free product story:
#   fake sensor → fb_api publish/readback → CTT mock gate
#
# Protocols: Modbus TCP, SLMP Binary 3E, EtherNet/IP, PROFINET CC-B.
# No PLC, no NIC, no CAP_NET_RAW. Not PI / ODVA / Modbus.org / Mitsubishi
# certification.
#
# Usage (from repo root or this directory):
#   examples/run_mock_flow.sh              # all four protocols
#   examples/run_mock_flow.sh all
#   examples/run_mock_flow.sh modbus
#   examples/run_mock_flow.sh slmp|ethernetip|profinet
#   BUILD_DIR=build-mock examples/run_mock_flow.sh
#   examples/run_mock_flow.sh --skip-configure   # reuse an already-configured tree
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

BUILD_DIR=${BUILD_DIR:-"$ROOT/build"}
SKIP_CONFIGURE=0
SKIP_BUILD=0
CONFIG_OVERRIDE=""
PROTOCOLS=()

usage() {
    cat <<EOF
usage: $0 [options] [all|modbus|slmp|ethernetip|profinet]...
  builds daemon/API + fake_sensor_app + CTT as needed
  for each protocol: fake_sensor_app --once (publish + same-session fb_read_*)
    then ctest -LE soak_ci -L <label>
  no args or 'all' runs Modbus TCP, SLMP Binary 3E, EtherNet/IP, PROFINET CC-B
  exits non-zero on failure

options:
  --skip-configure
  --skip-build
  --build-dir DIR
  --config JSON     override config for a single-protocol run
EOF
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

config_for_proto() {
    case "$1" in
        modbus) echo "$ROOT/config/example.fake_sensor.json" ;;
        slmp) echo "$ROOT/config/example.fake_sensor.slmp.json" ;;
        ethernetip) echo "$ROOT/config/example.fake_sensor.ethernetip.json" ;;
        profinet) echo "$ROOT/config/example.fake_sensor.profinet.json" ;;
        *) echo "" ;;
    esac
}

label_for_proto() {
    case "$1" in
        modbus) echo modbus ;;
        slmp) echo slmp ;;
        ethernetip) echo ethernetip ;;
        profinet) echo profinet ;;
        *) echo "" ;;
    esac
}

title_for_proto() {
    case "$1" in
        modbus) echo "Modbus TCP" ;;
        slmp) echo "SLMP Binary 3E" ;;
        ethernetip) echo "EtherNet/IP" ;;
        profinet) echo "PROFINET CC-B" ;;
        *) echo "$1" ;;
    esac
}

protocol_from_config() {
    local f="$1"
    local p
    p=$(sed -n 's/^[[:space:]]*"protocol"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$f" | head -n 1)
    normalize_proto "$p"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-configure) SKIP_CONFIGURE=1 ;;
        --skip-build) SKIP_BUILD=1 ;;
        --build-dir)
            if [ $# -lt 2 ]; then
                echo "missing --build-dir value" >&2
                exit 1
            fi
            BUILD_DIR=$2
            shift
            ;;
        --config)
            if [ $# -lt 2 ]; then
                echo "missing --config value" >&2
                exit 1
            fi
            CONFIG_OVERRIDE=$2
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
    if [ -n "$CONFIG_OVERRIDE" ]; then
        inferred=$(protocol_from_config "$CONFIG_OVERRIDE")
        if [ -z "$inferred" ]; then
            echo "could not infer protocol from $CONFIG_OVERRIDE" >&2
            exit 1
        fi
        PROTOCOLS=("$inferred")
    else
        PROTOCOLS=(all)
    fi
fi

EXPANDED=()
for p in "${PROTOCOLS[@]}"; do
    if [ "$p" = "all" ]; then
        EXPANDED+=(modbus slmp ethernetip profinet)
    else
        EXPANDED+=("$p")
    fi
done
PROTOCOLS=("${EXPANDED[@]}")

if [ -n "$CONFIG_OVERRIDE" ] && [ ${#PROTOCOLS[@]} -ne 1 ]; then
    echo "--config is only valid with a single protocol (got ${#PROTOCOLS[@]})" >&2
    exit 1
fi

echo "=== mock flow (no hardware; not certification) ==="
echo "root=$ROOT"
echo "build_dir=$BUILD_DIR"
echo "protocols=${PROTOCOLS[*]}"

if [ "$SKIP_CONFIGURE" -eq 0 ]; then
    cmake -S "$ROOT" -B "$BUILD_DIR" \
        -DBUILD_DAEMON=ON \
        -DBUILD_API=ON \
        -DBUILD_CTT=ON \
        -DENABLE_PN_TESTS=ON \
        -DENABLE_EIP_TESTS=ON \
        -DENABLE_MB_TESTS=ON \
        -DENABLE_SLMP_TESTS=ON
fi

if [ "$SKIP_BUILD" -eq 0 ]; then
    cmake --build "$BUILD_DIR" --target fake_sensor_app --target ctt
fi

APP="$BUILD_DIR/fake_sensor_app"
CTT="$BUILD_DIR/ctt"
if [ ! -x "$APP" ]; then
    echo "fake_sensor_app not found at $APP (need BUILD_DAEMON=ON BUILD_API=ON)" >&2
    exit 1
fi
if [ ! -x "$CTT" ]; then
    echo "ctt not found at $CTT (need BUILD_CTT=ON)" >&2
    exit 1
fi

run_one() {
    local proto="$1"
    local cfg label title n
    if [ -n "$CONFIG_OVERRIDE" ]; then
        cfg=$CONFIG_OVERRIDE
    else
        cfg=$(config_for_proto "$proto")
    fi
    label=$(label_for_proto "$proto")
    title=$(title_for_proto "$proto")

    if [ ! -f "$cfg" ]; then
        echo "config not found: $cfg" >&2
        exit 1
    fi

    echo
    echo "=== $title: fake sensor publish + fb_api readback ==="
    echo "config=$cfg"
    "$APP" --once "$cfg"

    echo
    echo "=== $title: CTT mock gate (in-process stack; not certification) ==="
    n=$(ctest --test-dir "$BUILD_DIR" -N -LE soak_ci -L "$label" | awk '/Total Tests:/{print $3}')
    if [ -z "${n:-}" ] || [ "$n" -eq 0 ]; then
        echo "no tests matched -LE soak_ci -L $label (is BUILD_CTT=ON?)" >&2
        exit 1
    fi
    echo "running $n $title CTT test(s)"
    ctest --test-dir "$BUILD_DIR" --output-on-failure -LE soak_ci -L "$label"
}

for p in "${PROTOCOLS[@]}"; do
    run_one "$p"
done

echo
echo "=== mock flow OK ==="
echo "fake values were written and read via fb_api; CTT mock passed for:"
echo "  ${PROTOCOLS[*]}"
echo "this is not PI / ODVA / Modbus.org / Mitsubishi certification."
