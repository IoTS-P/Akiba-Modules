# ExternalDynamicChecker

## Category

- IoT Firmware

## Description

To test whether the base address and entry point given is correct through emulation.

## Requirements and Dependencies

### Temp data required

- 🔴 `String base_address`: Base address.
- 🔵 (optional) `String entry_point`: Entry point, if not present, will try to find.

### Dependency

- 🔵 (optional) `org.iotsplab.akiba.process.ARMBaseFinder`: If entry point is not present and arch is ARM Cortex series, will try to recognize file start as interruption vector table and get entry point.
- 🔴 `org.iotsplab.akiba.process.StartupDynamicChecker`: Source of emulator.

### Database columns

- 🟢 `ENTRY_VALID TEXT`: "valid" for test valid, "invalid" for test invalid.

## Mechanism

Just check if the emulation with given base address and entry point can execute enough instructions (unique) and functions. The default criterion is not strict (just 20 unique instructions and 2 unique functions). We count unique instructions because sometimes you can execute forever with a instruction jumping to itself.