#!/usr/bin/env bash
# Start our DUT in the role a CODESYS SoftPLC master/controller would talk to.
#
# Fully automated path: Modbus TCP server (fake sensor) on 127.0.0.1:15560
# (or 0.0.0.0:15560 with --lan). SoftPLC / Windows IDE are NOT started here.
#
# This script never launches CODESYS Control. GitHub Actions and this cloud
# agent have no boot application. SoftPLC/IDE master side is MANUAL until
# the Development System can download an app (unsigned transfer may be DENY).
#
# Usage (repo root):
#   examples/run_codesys_dut.sh                 # Modbus DUT, wait until Ctrl+C
#   examples/run_codesys_dut.sh --stand-in     # DUT + CODESYS-shaped master soak
#   examples/run_codesys_dut.sh --lan          # bind 0.0.0.0 (LAN / Docker host)
#   examples/run_codesys_dut.sh --protocol ethernetip
#   examples/run_codesys_dut.sh --protocol profinet
#
# Not PI / ODVA / Modbus.org / Mitsubishi / CODESYS certification.
# No PREEMPT_RT, no CAP_NET_RAW, no :502.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

BUILD_DIR=${BUILD_DIR:-"$ROOT/build"}
SKIP_CONFIGURE=0
SKIP_BUILD=0
STANDIN=0
LAN=0
PROTOCOL=modbus
CONFIG_OVERRIDE=""
SECONDS_RUN=0
CYCLES=0
DUT_PID=""

usage() {
    cat <<EOF
usage: $0 [options]

Starts Fieldbus DUT as a device for CODESYS SoftPLC (master/controller).
Does NOT start SoftPLC or the Windows Development System.

  (default)     Modbus TCP server + fake_sensor; print SoftPLC IP/port; wait
  --stand-in    also run examples/codesys_shaped_modbus_master.py
                (CODESYS-shaped stand-in until SoftPLC has an app; not CODESYS)

options:
  --protocol modbus|ethernetip|profinet|slmp
  --lan                 use 0.0.0.0 bind configs (LAN / Docker host)
  --config JSON         override config path
  --seconds N           DUT lifetime (default: until SIGINT; stand-in: 4s)
  --cycles N            stand-in poll count (default 32)
  --build-dir DIR
  --skip-configure
  --skip-build
  -h, --help

SoftPLC should connect to:
  same host:     127.0.0.1:15560   (Modbus, unit 1)
  DUT in Docker: <docker-host-ip>:15560  (use --lan on DUT)
  EIP (manual):  127.0.0.1:44818 TCP / UDP 2222  (package required)
  PN (manual):   GSDML + real NIC; mock JSON does not speak on the wire
  SLMP:          not native in CODESYS — do not use this path for SoftPLC

See docs/codesys_master_io.md
EOF
}

banner() {
    echo "============================================================"
    echo "CODESYS SoftPLC master path — DUT side only"
    echo "SoftPLC / IDE master side is MANUAL until a boot app exists."
    echo "This process is not CODESYS. Not certification. No PREEMPT_RT."
    echo "============================================================"
}

normalize_proto() {
    case "$1" in
        modbus|modbus_tcp|mb) echo modbus ;;
        ethernetip|eip) echo ethernetip ;;
        profinet|pn) echo profinet ;;
        slmp) echo slmp ;;
        *) echo "" ;;
    esac
}

config_for() {
    local proto="$1"
    if [ -n "$CONFIG_OVERRIDE" ]; then
        echo "$CONFIG_OVERRIDE"
        return
    fi
    case "$proto" in
        modbus)
            if [ "$LAN" -eq 1 ]; then
                echo "$ROOT/config/example.codesys.modbus.json"
            else
                echo "$ROOT/config/example.fake_sensor.json"
            fi
            ;;
        ethernetip)
            if [ "$LAN" -eq 1 ] || [ "$STANDIN" -eq 1 ]; then
                echo "$ROOT/config/example.codesys.ethernetip.json"
            else
                echo "$ROOT/config/example.fake_sensor.ethernetip.json"
            fi
            ;;
        profinet)
            if [ "$LAN" -eq 1 ]; then
                echo "$ROOT/config/example.codesys.profinet.json"
            else
                echo "$ROOT/config/example.fake_sensor.profinet.json"
            fi
            ;;
        slmp)
            echo "$ROOT/config/example.fake_sensor.slmp.json"
            ;;
    esac
}

listen_hint() {
    local proto="$1"
    case "$proto" in
        modbus)
            echo "SoftPLC Modbus TCP Master / Slave device:"
            echo "  IP        127.0.0.1   (same Linux host as this DUT)"
            echo "  IP (LAN)  <this host's address>  (if DUT started with --lan)"
            echo "  Docker    host.docker.internal or docker-bridge gateway"
            echo "  Port      15560   (not privileged 502)"
            echo "  Unit ID   1"
            echo "  FC03      offset 0, length 16  → barcode_value (ASCII, 2 chars/reg)"
            echo "  FC03      offset 16, length 1    → temperature uint16 × 0.1 °C"
            if [ "$LAN" -eq 1 ]; then
                echo "  FC05      coil offset 0          → trigger (codesys.modbus.json only)"
            fi
            ;;
        ethernetip)
            echo "SoftPLC EtherNet/IP Scanner (package / complex-fieldbus license):"
            echo "  EDS       stacks/ethernetip/eds/FieldbusSensor.eds"
            echo "  TCP       127.0.0.1:44818   (or DUT IP with --lan live config)"
            echo "  UDP IO    2222"
            echo "  Input assembly 150 (64 bytes): barcode[0..31] + float32 temp @32"
            echo "  mock:true JSON does NOT bind sockets — use --lan for live Adapter"
            echo "  security_class 0 in example.codesys.ethernetip.json (no HMAC)"
            ;;
        profinet)
            echo "SoftPLC PROFINET Controller (package; CC-B / RT Class 1 only):"
            echo "  GSDML     stacks/profinet/gsdml/GSDML-V2.35-Fieldbus-PN-Device.xml"
            echo "  NameOfStation  sensor-line1"
            echo "  Cycle     8 ms, RT Class 1. Do not enable IRT / CC-C."
            echo "  mock JSON has no AF_PACKET — live needs a real NIC (not this default)"
            echo "  This helper does not require CAP_NET_RAW and will not set it."
            ;;
        slmp)
            echo "SLMP Binary 3E is NOT a native CODESYS fieldbus."
            echo "  DUT lab server (if you still start it): 127.0.0.1:15561"
            echo "  SoftPLC has no SLMP master. Use Modbus TCP for this hour of work."
            ;;
    esac
}

cleanup() {
    if [ -n "$DUT_PID" ] && kill -0 "$DUT_PID" 2>/dev/null; then
        kill -TERM "$DUT_PID" 2>/dev/null || true
        wait "$DUT_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

while [ $# -gt 0 ]; do
    case "$1" in
        --stand-in) STANDIN=1 ;;
        --lan|--bind-all) LAN=1 ;;
        --skip-configure) SKIP_CONFIGURE=1 ;;
        --skip-build) SKIP_BUILD=1 ;;
        --protocol)
            if [ $# -lt 2 ]; then
                echo "missing --protocol value" >&2
                exit 1
            fi
            PROTOCOL=$(normalize_proto "$2")
            if [ -z "$PROTOCOL" ]; then
                echo "unknown protocol: $2" >&2
                exit 1
            fi
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
                echo "unknown argument: $1" >&2
                usage >&2
                exit 1
            fi
            PROTOCOL=$n
            ;;
    esac
    shift
done

CFG=$(config_for "$PROTOCOL")
if [ ! -f "$CFG" ]; then
    echo "config not found: $CFG" >&2
    exit 1
fi

banner
echo "root=$ROOT"
echo "build_dir=$BUILD_DIR"
echo "protocol=$PROTOCOL"
echo "config=$CFG"
echo "stand_in=$STANDIN lan=$LAN"
echo
listen_hint "$PROTOCOL"
echo

if [ "$PROTOCOL" = "slmp" ]; then
    echo "refusing to claim a CODESYS SLMP master path."
    echo "Start a Modbus DUT instead: $0 --protocol modbus"
    exit 1
fi

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
if [ ! -x "$APP" ]; then
    echo "fake_sensor_app not found at $APP (need BUILD_DAEMON=ON BUILD_API=ON)" >&2
    exit 1
fi

if [ "$PROTOCOL" = "ethernetip" ] && [ "$LAN" -eq 0 ] && [ "$STANDIN" -eq 0 ]; then
    echo "NOTE: default EIP config is mock (no TCP 44818). For a live Adapter:"
    echo "  $0 --protocol ethernetip --lan"
    echo
fi

if [ "$PROTOCOL" = "profinet" ]; then
    echo "NOTE: default PN config is iface=mock. SoftPLC Controller needs a NIC"
    echo "  and is MANUAL. This helper will still run the fake sensor process image."
    echo
fi

DUT_ARGS=("$APP")
if [ "$STANDIN" -eq 1 ]; then
    if [ "$SECONDS_RUN" -gt 0 ]; then
        DUT_ARGS+=(--seconds "$SECONDS_RUN")
    elif [ "$CYCLES" -gt 0 ]; then
        # Keep DUT alive longer than the stand-in poll.
        DUT_ARGS+=(--seconds "$((CYCLES * 2 + 8))")
    else
        DUT_ARGS+=(--seconds 12)
    fi
elif [ "$SECONDS_RUN" -gt 0 ]; then
    DUT_ARGS+=(--seconds "$SECONDS_RUN")
fi
DUT_ARGS+=("$CFG")

echo "=== starting DUT (fake_sensor_app) ==="
echo "${DUT_ARGS[*]}"
"${DUT_ARGS[@]}" &
DUT_PID=$!

# Give fb_open + listen a moment (Modbus bind is in connect/start).
sleep 0.4
if ! kill -0 "$DUT_PID" 2>/dev/null; then
    wait "$DUT_PID" || true
    echo "DUT exited early" >&2
    exit 1
fi

MASTER="$ROOT/examples/codesys_shaped_modbus_master.py"
STANDIN_RC=0

if [ "$STANDIN" -eq 1 ]; then
    echo
    echo "=== CODESYS-shaped stand-in (not CODESYS) ==="
    if [ "$PROTOCOL" = "modbus" ]; then
        ST_ARGS=(python3 "$MASTER" --host 127.0.0.1 --port 15560 --protocol modbus)
        if [ "$CYCLES" -gt 0 ]; then
            ST_ARGS+=(--cycles "$CYCLES")
        elif [ "$SECONDS_RUN" -gt 0 ]; then
            ST_ARGS+=(--seconds "$SECONDS_RUN")
        else
            ST_ARGS+=(--cycles 32)
        fi
        "${ST_ARGS[@]}"
        STANDIN_RC=$?
    elif [ "$PROTOCOL" = "ethernetip" ]; then
        python3 "$MASTER" --host 127.0.0.1 --protocol ethernetip --eip-port 44818
        STANDIN_RC=$?
    else
        echo "no stand-in for protocol=$PROTOCOL (PN needs a real controller on L2)"
        STANDIN_RC=0
    fi
    echo
    echo "stand-in finished rc=$STANDIN_RC — still not a CODESYS app download."
    cleanup
    DUT_PID=""
    exit "$STANDIN_RC"
fi

echo
echo "DUT running pid=$DUT_PID"
echo "Point a CODESYS Modbus TCP Master at the IP/port printed above."
echo "Without IDE / boot application, SoftPLC will not poll this DUT."
echo "Until then, use: $0 --stand-in"
echo "Ctrl+C to stop."
wait "$DUT_PID"
DUT_PID=""
