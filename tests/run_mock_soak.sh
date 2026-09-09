#!/usr/bin/env bash
# Equipment-free timed soak of in-repo stacks (mock transport).
#
# Protocols: Modbus TCP, SLMP Binary 3E, EtherNet/IP Adapter Class 1,
# PROFINET CC-B RT Class 1. Sequential (jitter not mixed across protocols).
#
# NOT PI / ODVA / Modbus.org / Mitsubishi / CODESYS certification.
# No CAP_NET_RAW, no real NIC, no CC-C/IRT, no licensed Bundle copy.
#
# Usage (from repo root):
#   tests/run_mock_soak.sh                  # 3600s YAML default, sequential
#   tests/run_mock_soak.sh --seconds 1800   # 30 min each
#   tests/run_mock_soak.sh --seconds 7200   # 2 h each
#   tests/run_mock_soak.sh --protocol modbus --seconds 30
#   BUILD_DIR=build tests/run_mock_soak.sh --skip-configure --skip-build
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

BUILD_DIR=${BUILD_DIR:-"$ROOT/build"}
SKIP_CONFIGURE=0
SKIP_BUILD=0
SECONDS_OVERRIDE=""
REPORT_DIR=""
PROTOCOLS=()

usage() {
    cat <<EOF
usage: $0 [options] [all|modbus|slmp|ethernetip|profinet]...
  timed mock soak via ./build/ctt --scenario nightly/soak_nightly.yaml
  default: all four protocols, sequential, YAML duration_s (3600)
  exits non-zero on first failure

options:
  --seconds N         override soak wall time (CTT --seconds / CTT_SOAK_DURATION_S)
  --report-dir DIR    write ctt-report/v1 JSON per protocol
  --build-dir DIR
  --skip-configure
  --skip-build
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

scenario_for_proto() {
    case "$1" in
        modbus) echo "$ROOT/tests/scenarios/modbus/nightly/soak_nightly.yaml" ;;
        slmp) echo "$ROOT/tests/scenarios/slmp/nightly/soak_nightly.yaml" ;;
        ethernetip) echo "$ROOT/tests/scenarios/ethernetip/nightly/soak_nightly.yaml" ;;
        profinet) echo "$ROOT/tests/scenarios/profinet/nightly/soak_nightly.yaml" ;;
        *) echo "" ;;
    esac
}

title_for_proto() {
    case "$1" in
        modbus) echo "Modbus TCP" ;;
        slmp) echo "SLMP Binary 3E" ;;
        ethernetip) echo "EtherNet/IP" ;;
        profinet) echo "PROFINET CC-B RT1" ;;
        *) echo "" ;;
    esac
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --skip-configure) SKIP_CONFIGURE=1; shift ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        --seconds)
            SECONDS_OVERRIDE="${2:-}"
            shift 2
            ;;
        --seconds=*)
            SECONDS_OVERRIDE="${1#--seconds=}"
            shift
            ;;
        --report-dir)
            REPORT_DIR="${2:-}"
            shift 2
            ;;
        --report-dir=*)
            REPORT_DIR="${1#--report-dir=}"
            shift
            ;;
        --build-dir)
            BUILD_DIR="${2:-}"
            shift 2
            ;;
        --build-dir=*)
            BUILD_DIR="${1#--build-dir=}"
            shift
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "unknown option $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            n=$(normalize_proto "$1")
            if [[ -z "$n" ]]; then
                echo "unknown protocol $1" >&2
                usage >&2
                exit 2
            fi
            PROTOCOLS+=("$n")
            shift
            ;;
    esac
done

if [[ ${#PROTOCOLS[@]} -eq 0 ]]; then
    PROTOCOLS=(all)
fi

expanded=()
for p in "${PROTOCOLS[@]}"; do
    if [[ "$p" == all ]]; then
        expanded+=(modbus slmp ethernetip profinet)
    else
        expanded+=("$p")
    fi
done
PROTOCOLS=("${expanded[@]}")

if [[ "$SKIP_CONFIGURE" -eq 0 ]]; then
    cmake -S "$ROOT" -B "$BUILD_DIR" \
        -DBUILD_DAEMON=OFF -DBUILD_CTT=ON \
        -DENABLE_PN_TESTS=ON -DENABLE_EIP_TESTS=ON \
        -DENABLE_MB_TESTS=ON -DENABLE_SLMP_TESTS=ON
fi
if [[ "$SKIP_BUILD" -eq 0 ]]; then
    cmake --build "$BUILD_DIR" --target ctt
fi

CTT="$BUILD_DIR/ctt"
if [[ ! -x "$CTT" ]]; then
    echo "missing $CTT (configure with BUILD_CTT=ON)" >&2
    exit 1
fi

if [[ -n "$REPORT_DIR" ]]; then
    mkdir -p "$REPORT_DIR"
fi

echo "=== mock soak (internal gate, not certification) ==="
echo "utc_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "tz_note=timestamps UTC; Asia/Seoul = UTC+9"
echo "commit=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
echo "seconds_override=${SECONDS_OVERRIDE:-yaml_duration_s}"
echo "protocols=${PROTOCOLS[*]}"
echo

fail=0
for p in "${PROTOCOLS[@]}"; do
    sc=$(scenario_for_proto "$p")
    title=$(title_for_proto "$p")
    echo "=== $title ==="
    echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ) scenario=$sc"
    cmd=("$CTT" --scenario "$sc" --transport=mock)
    if [[ -n "$SECONDS_OVERRIDE" ]]; then
        cmd+=(--seconds "$SECONDS_OVERRIDE")
    fi
    if [[ -n "$REPORT_DIR" ]]; then
        cmd+=(--report "$REPORT_DIR/${p}.json")
    fi
    echo "+ ${cmd[*]}"
    if "${cmd[@]}"; then
        echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ) $p PASS"
    else
        echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ) $p FAIL" >&2
        fail=1
        break
    fi
    echo
done

echo "utc_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [[ "$fail" -ne 0 ]]; then
    echo "mock soak FAILED (not a certification result)" >&2
    exit 1
fi
echo "mock soak PASS (internal; not PI/ODVA/Modbus.org/Mitsubishi/CODESYS)"
exit 0
