# AddressSpaceAnalyzer

## Category

- IoT Firmware

## Description

To emulate a firmware with given base address, entry point, stack pointer and memory sections using `StepInEmulator`. It will analyze all direct dataflows between a memory address to another memory address, and aggregate the results to try to find out the range of data in the firmware file.

For ARM Cortex series, it can trace the copies of interrupt vector table.

## Requirements and Dependencies

### Temp data required

- 🔴 `BasicLoadMetadata load_metadata`: Mandatory data for loading the firmware file into Ghidra emulator.
- 🔵 (optional) `ArmcmIVT ivt`: Used in ARM Cortex series to trace the copies of interrupt vector table.

### Dependency

- 🔴 `org.iotsplab.akiba.process.IoTGeneralStructures`: Used to define the structures of IoT firmware.
- 🔵 (optional) `org.iotsplab.akiba.process.ARMBaseFinder`: Used in ARM Cortex series to get the interrupt vector table information.

### Database columns

- 🟢 `DATA_FILE_OFFSET INTEGER`: The offset of defined data in the firmware file.
- 🟢 `DATA_SIZE INTEGER`: The size of defined data.
- 🟢 `DATA_MAP_START INTEGER`: The start of real mapping address of defined data in runtime execution.

## Mechanism

In small firmwares loaded in a whole, the data is often located **right after the codes** and needs to be copied to the data sections. Also, the batch zero-byte fills symbolizes the **initialization of `.bss` section** for uninitialized global variables. We monitor the data copies and zero-byte fills to find out where the data should be located.

## Note

This module contains detection of continuous zero-byte fills, but will not save the behavior into database.