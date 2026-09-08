(*
 * IEC 61131-3 ST for a CODESYS Control SL 2-hour demo as PROFINET Controller.
 * Map I/O in the device tree to these variables (AT %I / %Q or I/O mapping).
 * Cycle time must be >= 8 ms (GSDML MinDeviceInterval=256).
 *)
PROGRAM PLC_PRG
VAR
    barcode AT %IB0 : ARRAY[0..31] OF BYTE;
    trigger AT %QB0 : BYTE;
    i : INT;
    saw_beta : BOOL;
END_VAR

trigger := 16#5A;

saw_beta := TRUE;
FOR i := 0 TO 9 DO
    IF barcode[i] <> BYTE#0 THEN
        ; (* non-zero input from device *)
    END_IF
END_FOR
