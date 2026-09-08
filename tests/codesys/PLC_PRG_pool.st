(*
 * CODESYS Control SL — Sensor pool IEC program.
 *
 * One SoftPLC, three fieldbuses (CODESYS does not speak SLMP or CC-Link):
 *   Ethernet → Modbus TCP Master   → this repo's Modbus server (port 1502)
 *   Ethernet → EtherNet/IP Scanner → this repo's EIP adapter  (44818 / asm 150)
 *   Ethernet → PN-Controller       → this repo's PN Device    (GSDML FB-ARCH)
 *
 * Map I/O in the device tree onto the AT addresses below, then Login/Download/Run.
 * Cycle time of the IEC task must be >= 8 ms.
 *
 * Expected live values from demos/sensor/sensor_demo:
 *   barcode  ASCII "BETA-PN-IN/NNNNNN"
 *   temp     UINT  200..350  (0.1 °C)
 *   humidity UINT  300..700  (0.1 %RH)
 *   seq      UINT  incrementing
 *)
PROGRAM PLC_PRG
VAR
    (* --- PROFINET Device slot 1, 32 byte in / 8 byte out --- *)
    pn_barcode AT %IB0 : ARRAY[0..15] OF BYTE;
    pn_temp    AT %IW16 : UINT;
    pn_hum     AT %IW18 : UINT;
    pn_seq     AT %IW20 : UINT;
    pn_trigger AT %QB0 : BYTE;

    (* --- Modbus TCP Master holding 40001.., unit 1 --- *)
    mb_barcode AT %MW100 : ARRAY[0..15] OF BYTE; (* map Holding 0..15 *)
    mb_temp    AT %MW116 : UINT;
    mb_hum     AT %MW117 : UINT;
    mb_seq     AT %MW118 : UINT;

    (* --- EtherNet/IP Scanner T->O assembly 150 --- *)
    eip_barcode AT %IB64 : ARRAY[0..31] OF BYTE;
    eip_temp    AT %IW96 : UINT;
    eip_hum     AT %IW98 : UINT;
    eip_seq     AT %IW100 : UINT;

    i : INT;
    pn_ok : BOOL;
    mb_ok : BOOL;
    eip_ok : BOOL;
    last_pn_seq : UINT;
    last_mb_seq : UINT;
    last_eip_seq : UINT;
END_VAR

pn_trigger := 16#5A;

pn_ok := FALSE;
FOR i := 0 TO 9 DO
    IF pn_barcode[i] <> BYTE#0 THEN
        pn_ok := TRUE;
    END_IF
END_FOR
IF pn_seq <> last_pn_seq THEN
    pn_ok := TRUE;
END_IF
last_pn_seq := pn_seq;

mb_ok := (mb_seq <> last_mb_seq);
last_mb_seq := mb_seq;

eip_ok := (eip_seq <> last_eip_seq);
last_eip_seq := eip_seq;
