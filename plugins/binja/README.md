# Symbolicate Plugin

Author: **blacktop**

_Imports `ipsw` **symbols.json** files into Project creating functions (if they don't exist) and adding symbols._

## Description:

This plugin accompanies the [symbolicator](https://github.com/blacktop/symbolicator) repo and takes the `symbols.json` output of running `ipsw kernel symbolicate` and applies it to a kernelcache in Binary Ninja creating functions if they don't exist.

## Getting Started

### Install the plugin

On macOS

```bash
bash install.sh
```

### Run the plugin

Launch via `Plugin` drop down:

![bn-plugin-lauch](docs/bn-plugin-lauch.png)

Pick your `symbols.json` file:

![bn-plugin-choose](docs/bn-plugin-choose.png)

So many symbols 😍

![bn-plugin-done](docs/bn-plugin-done.png)

Happy reversing!

## License

MIT Copyright (c) 2024 blacktop.