# EntryFinder

## Category

- IoT Firmware

## Description

To get a small set of possible entry point of a firmware.

## Requirements and Dependencies

### Temp data produced

- 🔴 `List<Function>> entry_point_candidates`: Candidates of the entry point got

### API offered

- 🟠 `suspend fun updateResult`: Refind the candidates of the entry point (the functions can be changed so need to redo the process to get the latest result)

## Mechanism

The entry point of a binary file must have no xrefs to it, so we can simply find all functions that no one else calls them. However, there could be many functions satisfying this condition, so there is some additional criteria to shrink the range further:

1. Functions containing no return: The entry point must cannot return (at least in most cases), we can leave those alone who can return.
2. Functions containing any call: The entry point should call or jump to somewhere else, we can leave those alone who don't call. (Jumps at the end of the function to somewhere out of the function is also considered as a call)
3. Functions containing no parameter: The entry point must have 0 parameters as no one could send parameters to it. we can leave those alone who have any parameter. (through deep analysis of Ghidra we can infer the function prototype, although it's not 100% accurate, Ghidra would not likely to treat a function of no parameter as the one of any parameter)

After those filters, the candidates could be very few (tested to be about less than 1% of overall functions)

## Note

If the entry point failed to be recognized as codes, EntryFinder cannot get it.