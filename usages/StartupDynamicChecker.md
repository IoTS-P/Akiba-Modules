# StartupDynamicChecker

## Category

- IoT Firmware

## Description

To check the validity of base address and entry point through emulations from the entry point. If enough instructions and functions are executed, the base and the entry point will be regarded as valid.

## Requirements and Dependencies

### Temp data required

- 🔴 `Address load_metadata`: Metadata containing base address, entry point, initial stack pointer value, memory sections to load.

### Dependency

- 🔴 `org.iotsplab.akiba.process.IoTGeneralStructures`: Used to define the structures of IoT firmware.

### Database column

- 🟢 `ENTRY_VALID TEXT`: "valid" for test valid, "invalid" for test invalid.

Just check if the emulation with given base address and entry point can execute enough instructions (unique) and functions. The default criterion is not strict (just 20 unique instructions and 2 unique functions). We count unique instructions because sometimes you can execute forever with a instruction jumping to itself.