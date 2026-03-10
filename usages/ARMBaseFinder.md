# ARMBaseFinder

## Category

- IoT Firmware

## Description

To find the base address, entry point, Interruption vector table of an ARM Cortex series firmware.

## Requirements and Dependencies

### Temp data produced

- 🔴 `BasicLoadMetadata load_metadata`: Mandatory data for loading the firmware file into Ghidra emulator.
- 🔴 `ArmcmIVT ivt`: Used in ARM Cortex series to trace the copies of Interruption vector table.

### Dependency

- 🔴 `org.iotsplab.akiba.process.HTTPServer`: Used to send progress for matching base address.
- 🔴 `org.iotsplab.akiba.process.IoTGeneralStructures`: Used to define the structures of IoT firmware.
- 🔴 `org.iotsplab.akiba.process.ProgramServer`: Used to accelerate matching process.

### Database columns

- 🟢 `BASE_ADDRESS INTEGER`: Base address got.
- 🟢 `ENTRY_POINT INTEGER`: Entry point got.
- 🟢 `IVT_START INTEGER`: Start address of Interruption vector table.

## Mechanism

The nature of finding base address is **function address matching**. Considering that ARM Cortex series has a special structure: the **Interruption vector table** (IVT for later mentions), which contains a lot of function addresses. So our strategy of finding the base address can be concluded as:

1. Find all candidate IVTs in a firmware (IVT has some features, we designed a fairly complicated heuristic method to get all candidates) and get all function pointers in it as $F_i$.
2. Get all functions after auto analysis by Ghidra and get their start addresses as $F$.
3. $\forall f_i \in F_i$, $\forall f \in F$, calculate $f_i - f$ as candidate base address. get all subtraction results in a repeatable set $S$.
4. Get candidates that repeated most often, go through several ranges of filters, to get a list of final candidates.
5. Set the base address to those final candidates, and check again the level that the IVT matches (using a scoring algorithm). The one that gains the highest score is the selected IVT, and we can infer the entry point, master stack pointer and base address of the firmware.

## Note

❗ **Performance Warning**: This module may take a long time and cost a lot of memory to run.