# CODESYS Control SL 2-hour demo (PROFINET Controller)

This Device can be brought up under **CODESYS Control for Linux SL / Win SL**
in the official **two-hour demo** (no paid license; runtime stops until
restart). This repository does **not** ship the CODESYS binary.

An empty Control SL process is **not** a PROFINET Controller. The IEC app
(Ethernet → PN-Controller → this GSDML) is compiled in **CODESYS Development
System** on Windows and downloaded to the runtime. Without that download there
is no AR, even if `codesyscontrol` is running.

In this repo the on-wire stand-in (same CM order, not the CODESYS binary) is:

```
cmake --build build --target pn_codesys_beta pn_device_run
bash tests/run_pn_codesys_beta.sh
```

That script walks the same CM path CODESYS uses (DCP scan / Nominate /
Connect+AlarmCR / sequential Write / PrmEnd / AppReady / 8 ms RTC1 / Release).
It is **not** a CODESYS binary and not PI ART. RTC1 TX is phase-locked on an
absolute 8 ms grid (skip missed cycles, no period stretch). The beta asserts
≥100 input frames in 1.2 s and mean interval near 8 ms.

## What you need on a PC (2-hour session)

1. [CODESYS Development System](https://store.codesys.com/) (Windows).
2. [CODESYS Control for Linux SL](https://store.codesys.com/en/codesys-control-linux-sl-1.html)
   or Control Win SL. Download is free; without a license key the PLC runs
   **two hours**, then restart the runtime.
3. PROFINET Controller is included in the Control SL runtime package.
   Configure Ethernet as in the CODESYS help (`SysEthernet` ProtocolFilter=3
   on Linux).

## Project (about 15 minutes)

1. **Device Repository** → **Install** →
   `stacks/profinet/gsdml/GSDML-V2.35-Fieldbus-PN-Device.xml`
   Catalog: Fieldbuses → Profinet IO → Profinet IO Slave → **FB-ARCH PN Device**.
2. New standard project → device **CODESYS Control for Linux SL** (or Win SL).
3. Add **Ethernet** → **PN-Controller** → add **FB-ARCH PN Device**.
4. On the device:
   - Station name: `sensor-line1` (must match `protocol_params.device_name`)
   - IP: `192.168.0.10` (or the NIC you actually use)
   - Cycle: **8 ms** default (SendClock 32 × ReductionRatio 8). GSDML also
     allows 16/32/64/128/256/512 ms. Do not set 1 ms.
   - Slot 1: IO module already in the GSDML (32 byte in / 8 byte out).
5. I/O mapping: copy `tests/codesys/PLC_PRG.st` into `PLC_PRG`.
6. On the Linux target running this stack:

```
sudo setcap cap_net_raw,cap_net_bind_service=+ep ./build/multiproto_daemon
./build/multiproto_daemon config/example.profinet.json
```

   Use the same NIC, station name, and IPv4 as the CODESYS device config.
   `security_class` must stay **0**. CODESYS does not send the stack-local HMAC
   blocks. DCP Nominate (Set Name) runs **before** Connect, so SC1 AR write
   protect does not block it. SNMP topology uses Get, not Set.

7. Login, download, start. **Scan for Devices** on PN-Controller should see
   `sensor-line1`. After RUN, `%IB0..31` should update and `%QB0=16#5A` is the
   trigger byte.

8. Demo limit: after two hours the SoftPLC stops. Restart `codesyscontrol`
   (Linux) or the Control Win tray app and login again.

## Linux SL runtime (verified 4.22.0.0)

Store SKUs: Control Linux SL `2302000005-SW`, Edge Gateway for Linux `000120`.
WIBU **CodeMeter-lite** is a package dependency (`codemeter | codemeter-lite`).
Official User Runtime DEB (driver-only / lite, amd64, 9.10):

```
https://www.wibu.com/support/user/user-software/file/download/17974.html?tx_wibudownloads_downloadlist%5BdirectDownload%5D=directDownload&tx_wibudownloads_downloadlist%5BuseAwsS3%5D=0
```

`tests/codesys/try_install_codesys.sh` logs into the Store, accepts the EULA
(`form_key` cookie + `license/get` + `license/accept`), downloads the
`.package` files, extracts amd64 debs, and starts the binaries when PID 1 is
not systemd. Then `dpkg -i` CodeMeter-lite, `codesyscontrol_linux_*_amd64.deb`
from the Control SL `.package`, and `codesysedge_edgeamd64_*_amd64.deb` from
the Edge Gateway `.package`.

If PID 1 is not systemd, start the binaries directly (root, for raw Ethernet):

```
sudo /etc/init.d/codemeter start
sudo env LD_LIBRARY_PATH=/opt/codesys/lib /opt/codesys/bin/codesyscontrol.bin /etc/codesyscontrol/CODESYSControl.cfg
sudo env LD_LIBRARY_PATH=/opt/codesysedge/lib /opt/codesysedge/bin/codesysedge.bin /etc/codesysedge/Gateway.cfg
```

Add to `CODESYSControl_User.cfg` (CODESYS help):

```
[SysEthernet]
Linux.PACKET_QDISC_BYPASS=1
Linux.ProtocolFilter=3
```

Demo listen ports seen on Ubuntu 24.04 amd64: Gateway **1217/tcp**, runtime
**11740/tcp**, network scan **1740/udp** (PLC) and **1743/udp** (Gateway),
OPC UA **4840/tcp**, CodeMeter **22350/tcp**.

CODESYS does **not** release Control SL for containers/VMs. A cloud VM can
still start the 2-hour demo, but IRT/XDP and support are out of scope, and a
Windows IDE on another network cannot reach a private `172.30.0.0/24` runtime.

## Do not expect

- PI certification, ART, or TEDCheck from this session.
- IRT / RT Class 3 (GSDML does not claim it; Connect RT_CLASS_3 is rejected).
- VendorID `0xABCD` is not PI-assigned; some CODESYS versions only warn.
- `Tools → Generate PROFINET Device from GSDML` is the **opposite** role
  (making a CODESYS Device). Use **Device Repository → Install** so CODESYS
  is the **Controller**.
