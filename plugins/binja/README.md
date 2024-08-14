# Symbolicate Plugin

Author: **blacktop**

_Imports `ipsw` symbols.json files into Project creating functions (if they don't exist) and adding symbols._

## Description:

This plugin accompanies the [symbolicator](https://github.com/blacktop/symbolicator) and takes the `symbols.json` output of running `ipsw kernel symbolicate` and applies it to a kernelcache in Binary Ninja creating functions if they don't exist.

## License

MIT Copyright (c) 2024 blacktop.