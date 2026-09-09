#!/usr/bin/env bash
# Equipment-free product story:
#   fake sensor → fb_api publish/readback → CTT Modbus mock gate
#
# No PLC, no NIC, no CAP_NET_RAW. Not PI / ODVA / Modbus.org certification.
#
# Usage (from repo root or this directory):
#   examples/run_mock_flow.sh
#   BUILD_DIR=build-mock examples/run_mock_flow.sh
#   examples/run_mock_flow.sh --skip-configure   # reuse an already-configured tree
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

BUILD_DIR=${BUILD_DIR:-"$ROOT/build"}
SKIP_CONFIGURE=0
SKIP_BUILD=0
CONFIG="$ROOT/config/example.fake_sensor.json"

usage() {
    cat <<EOF
usage: $0 [--skip-configure] [--skip-build] [--build-dir DIR] [--config JSON]
  builds daemon/API + fake_sensor_app + CTT as needed
  runs fake_sensor_app --once (publish + same-session fb_read_*)
  then ctest -LE soak_ci -L modbus
  exits non-zero on failure
EOF
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
            CONFIG=$2
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

if [ ! -f "$CONFIG" ]; then
    echo "config not found: $CONFIG" >&2
    exit 1
fi

echo "=== mock flow (no hardware; not certification) ==="
echo "root=$ROOT"
echo "build_dir=$BUILD_DIR"
echo "config=$CONFIG"

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

echo
echo "=== 1) fake sensor publish + fb_api readback ==="
"$APP" --once "$CONFIG"

echo
echo "=== 2) CTT Modbus mock gate (in-process stack; not certification) ==="
n=$(ctest --test-dir "$BUILD_DIR" -N -LE soak_ci -L modbus | awk '/Total Tests:/{print $3}')
if [ -z "${n:-}" ] || [ "$n" -eq 0 ]; then
    echo "no tests matched -LE soak_ci -L modbus (is BUILD_CTT=ON?)" >&2
    exit 1
fi
echo "running $n Modbus CTT test(s)"
ctest --test-dir "$BUILD_DIR" --output-on-failure -LE soak_ci -L modbus

echo
echo "=== mock flow OK ==="
echo "fake values were written and read via fb_api; CTT Modbus mock passed."
echo "this is not PI / ODVA / Modbus.org certification."
