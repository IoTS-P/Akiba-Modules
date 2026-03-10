# FunctionFinder

## Category

- IoT Firmware

## Description

Try to find functions that is not recognized by Ghidra and define them.

## Requirements and Dependencies

### Dependency

- 🔴 (Optional) `org.iotsplab.akiba.process.ARMBaseFinder`: Used when target is ARM Cortex series, used to skip file start as a default interruption vector table.

## Mechanism

There contains several methods to find functions:

1. Find all direct call instructions BRUTELY (because Ghidra will analyze call target, so only by finding brutely can we find extra direct calls that is not analyzed yet), and try to let Ghidra auto-analyze the target.
2. There could be some undefined bytes between functions, actually they are most likely to be functions, so we can try to disassemble and define functions in these gaps. (Need to consider former bytes of the first function and latter bytes of the last function)
3. In ARM Cortex series, some unimplemented interruption functions could be a dead loop. Sometimes they can make up a large proportion of function pointers in IVT. We can search for bytes '\xFE\xE7' to find them and define them as functions, to raise the accuracy of `ARMBaseFinder`.
4. Undefine all codes that doesn't belong to any functions, a lot of these codes are actually data.