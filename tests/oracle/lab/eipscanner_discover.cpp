// EtherNet/IP lab oracle: discovery with EIPScanner's DiscoveryManager.
// Sends ListIdentity over UDP (broadcast or unicast) like RSLinx browse and
// prints every reply. Repository code is not used (oracle independence).
//
// usage: eipscanner_discover <broadcast_or_unicast_ip> [port]
// output: "FOUND <n>" then one "DEV name=... vendor=... serial=... status=... addr=ip:port" per device
#include <DiscoveryManager.h>
#include <utils/Logger.h>
#include <cstdio>
#include <cstdlib>
using namespace eipScanner;
int main(int argc, char **argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: %s <addr> [port]\n", argv[0]); return 2; }
    utils::Logger::setLogLevel(utils::LogLevel::ERROR);
    int port = argc > 2 ? std::atoi(argv[2]) : 0xAF12;
    DiscoveryManager dm(argv[1], port, std::chrono::milliseconds(1000));
    auto items = dm.discover();
    std::printf("FOUND %zu\n", items.size());
    for (auto &it : items) {
        auto &id = it.identityObject;
        std::printf("DEV name=%s vendor=%u serial=%u status=0x%04x addr=%s\n",
                    id.getProductName().c_str(), id.getVendorId(), id.getSerialNumber(),
                    id.getStatus(), it.socketAddress.toString().c_str());
    }
    return 0;
}
