# ProgramServer

## Category

- IoT Firmware

## Description

Offers some APIs for performance.

## Requirements and Dependencies

### API offered

- 🟠 `fun getFunctionContaining(address: Long): Function?`: A faster method to get the function containing a given address.
- 🟠 `fun getFunctionStart(function: Function): Long`: A faster method to get the function start.

## Mechanism

By building a hashmap of functions and addresses, we can be faster to get the function containing a given address, and get a function start, because Ghidra need to dynamically find the functions.