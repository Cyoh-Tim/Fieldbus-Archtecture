# CODESYS Control SL 2-hour demo (PROFINET Controller)

This Device can be brought up under **CODESYS Control for Linux SL / Win SL**
in the official **two-hour demo** (no paid license; runtime stops until
restart). This repository does **not** ship the CODESYS binary. The Store
package is account-gated and the Development System is Windows, so this Linux
agent cannot install or log into a real CODESYS PLC.

In this environment the stand-in is:

```
cmake --build build --target pn_codesys_beta pn_device_run
bash tests/run_pn_codesys_beta.sh
```

That script walks the same CM path CODESYS uses (DCP scan / Nominate /
Connect+AlarmCR / sequential Write / PrmEnd / AppReady / 8 ms RTC1 / Release).
It is **not** a CODESYS binary and not PI ART.

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
   - Cycle: **8 ms** (SendClock 32 × ReductionRatio 8). Do not set 1 ms.
   - Slot 1: IO module already in the GSDML (32 byte in / 8 byte out).
5. I/O mapping: copy `tests/codesys/PLC_PRG.st` into `PLC_PRG`.
6. On the Linux target running this stack:

```
sudo setcap cap_net_raw,cap_net_bind_service=+ep ./build/multiproto_daemon
./build/multiproto_daemon config/example.profinet.json
```

   Use the same NIC, station name, and IPv4 as the CODESYS device config.
   `security_class` must stay **0**. CODESYS does not send the stack-local HMAC
   blocks.

7. Login, download, start. **Scan for Devices** on PN-Controller should see
   `sensor-line1`. After RUN, `%IB0..31` should update and `%QB0=16#5A` is the
   trigger byte.

8. Demo limit: after two hours the SoftPLC stops. Restart `codesyscontrol`
   (Linux) or the Control Win tray app and login again.

## Do not expect

- PI certification, ART, or TEDCheck from this session.
- IRT / RT Class 3 (GSDML does not claim it; Connect RT_CLASS_3 is rejected).
- VendorID `0xABCD` is not PI-assigned; some CODESYS versions only warn.
- `Tools → Generate PROFINET Device from GSDML` is the **opposite** role
  (making a CODESYS Device). Use **Device Repository → Install** so CODESYS
  is the **Controller**.
