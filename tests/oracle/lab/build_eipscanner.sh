#!/usr/bin/env bash
# EIPScanner (독립 오픈소스 EtherNet/IP 스캐너, MIT, https://github.com/nimbuscontrols/EIPScanner) 를
# 고정 커밋으로 받아 빌드하고, 랩 테스트용 Class 1 originator(eipscanner_originator)를 만든다.
#
#   tests/oracle/lab/build_eipscanner.sh <출력 디렉토리>
#   EIP_LAB_SCANNER=<출력 디렉토리>/eipscanner_originator pytest tests/oracle/test_eip_lab.py
#
# 필요: git, cmake, g++. 저장소 코드는 쓰지 않는다 (오라클 독립성).
set -euo pipefail
OUT=$(realpath -m "${1:?출력 디렉토리}")
COMMIT=12c89a57ec2e7449efb1348be52af10be9ef9701
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"
if [ ! -d "$OUT/EIPScanner/.git" ]; then
    git clone -q https://github.com/nimbuscontrols/EIPScanner.git "$OUT/EIPScanner"
fi
git -C "$OUT/EIPScanner" fetch -q --depth 1 origin "$COMMIT" 2>/dev/null || true
git -C "$OUT/EIPScanner" checkout -q "$COMMIT"
cmake -S "$OUT/EIPScanner" -B "$OUT/EIPScanner/build" -DCMAKE_BUILD_TYPE=Release \
      -DENABLE_EXAMPLES=OFF -DTEST_ENABLED=OFF >/dev/null
cmake --build "$OUT/EIPScanner/build" -j"$(nproc)" --target EIPScannerS >/dev/null
g++ -std=c++14 -O1 -I"$OUT/EIPScanner/src" -o "$OUT/eipscanner_originator" \
    "$HERE/eipscanner_originator.cpp" "$OUT/EIPScanner/build/src/libEIPScannerS.a" -lpthread
echo "$OUT/eipscanner_originator"
