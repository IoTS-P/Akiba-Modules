# StringAdder

## Category

- General

## Description

Find strings that is not automatically defined by Ghidra.

## Mechanism

Use Ghidra's string searching api to search all ascii character sequences. In default, we search:
- char sequences longer than 5 bytes and end with '\0'
- char sequences containing UNIX color control chars, like '\x1b[0;31m'

There could be some small strings shorter than 5 bytes that cannot be recognized, we will later explore gaps between 2 strings and try to fill it by defining small strings.