# ProgramInitialization

## Category

- IoT Firmware

## Description

A module to finish general instructions for all binaries.

## Mechanism

What we need to do:

1. Former checks of the program:
   - Won't analyze files larger them 10MiB.
2. Finish auto analysis of a program. (Enable aggressive instruction finder in default)
3. If auto analysis failed to get no less than 10 functions, then the binary file will be regarded as invalid, namely `Not a valid firmware`, and will be recorded into database, the task will be marked to be failed.