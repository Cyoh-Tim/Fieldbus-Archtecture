// Class 1 originator built on EIPScanner (independent EtherNet/IP scanner) for the
// veth lab tests (tests/oracle/test_eip_lab.py). Does not use repository code.
//
//   eipscanner_originator <target-ip> <seconds> <rpi-us> <o2t-data> <t2o-data> <run-idle 0|1>
//
// Connection path: config 100, output (O->T) 101, input (T->O) 150 — the assemblies of
// tests/oracle/dut/eip_oracle_adapter.c. EIPScanner adds the 2-byte sequence count and,
// with run-idle=1, the 32-bit Run/Idle header to the O->T size (Logix default format).
// O->T data is A1 A2 A3 A4. Prints:
//   FO ok | FO failed
//   RESULT rx=<T->O packets> last=<last T->O data hex> open_at_end=<0|1>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <cip/connectionManager/NetworkConnectionParams.h>
#include "ConnectionManager.h"
#include "SessionInfo.h"
#include "utils/Logger.h"

using eipScanner::ConnectionManager;
using eipScanner::SessionInfo;
using eipScanner::cip::connectionManager::ConnectionParameters;
using eipScanner::cip::connectionManager::NetworkConnectionParams;
using eipScanner::utils::Logger;
using eipScanner::utils::LogLevel;

int main(int argc, char **argv) {
  if (argc < 7) {
    std::fprintf(stderr, "usage: %s ip seconds rpi_us o2t t2o run_idle\n", argv[0]);
    return 2;
  }
  const int secs = std::atoi(argv[2]);
  const int rpi = std::atoi(argv[3]);
  const int o2t = std::atoi(argv[4]);
  const int t2o = std::atoi(argv[5]);
  Logger::setLogLevel(LogLevel::INFO);

  auto si = std::make_shared<SessionInfo>(argv[1], 0xAF12);
  ConnectionManager cm;
  ConnectionParameters p;
  p.connectionPath = {0x20, 0x04, 0x24, 100, 0x2C, 101, 0x2C, 150};
  p.o2tRealTimeFormat = std::atoi(argv[6]) != 0;
  p.originatorVendorId = 0x1234;
  p.originatorSerialNumber = 0x5678;
  p.connectionSerialNumber = 0x0042;
  p.o2tNetworkConnectionParams |= NetworkConnectionParams::P2P |
                                  NetworkConnectionParams::SCHEDULED_PRIORITY | o2t;
  p.t2oNetworkConnectionParams |= NetworkConnectionParams::P2P |
                                  NetworkConnectionParams::SCHEDULED_PRIORITY | t2o;
  p.o2tRPI = rpi;
  p.t2oRPI = rpi;
  p.transportTypeTrigger |= NetworkConnectionParams::CLASS1;

  long rx = 0;
  std::string last;
  auto io = cm.forwardOpen(si, p);
  auto conn = io.lock();
  if (!conn) {
    std::printf("FO failed\nRESULT rx=0 last= open_at_end=0\n");
    return 0;
  }
  std::printf("FO ok\n");
  conn->setDataToSend(std::vector<uint8_t>{0xA1, 0xA2, 0xA3, 0xA4});
  conn->setReceiveDataListener([&](auto, auto, auto data) {
    rx++;
    std::ostringstream ss;
    for (auto b : data) {
      char t[3];
      std::snprintf(t, sizeof(t), "%02x", b);
      ss << t;
    }
    last = ss.str();
  });
  const auto t0 = std::chrono::steady_clock::now();
  while (cm.hasOpenConnections() &&
         std::chrono::steady_clock::now() - t0 < std::chrono::seconds(secs)) {
    cm.handleConnections(std::chrono::milliseconds(rpi / 2000 + 1));
  }
  const bool open = cm.hasOpenConnections();
  std::printf("RESULT rx=%ld last=%s open_at_end=%d\n", rx, last.c_str(), open ? 1 : 0);
  if (open) {
    cm.forwardClose(si, io);
  }
  return 0;
}
