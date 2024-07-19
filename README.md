# symbolicator

> `ipsw` symbolication signatures

## What 🤔

This repo contain's `ipsw`'s symbolication signature files.

## Getting Started

Get the signatures

```bash
git clone https://github.com/blacktop/symbolicator.git
```

Symbolicate a kernelcache

```bash
ipsw kernel sym KC --json --signatures /path/to/symbolicator-repo/kernel
```

Install IDA Plugin

```bash
ida/plugins/install.sh
```

Now you can apply the symbols to you kernelcache in IDA by pressing `Alt+F8`

![ida-pluging](ida/docs/ida.png)

## Generate NEW signatures

First open a macOS KDK kernel or extension with symbol information and wait until it's done analyzing

You can set these ENV VARS to control the the outputed signature's metadata

- `TARGET` The target binary. (e.g. com.apple.driver.AppleHIDKeyboard)
- `MAX_VERSION` The maximum version of the target binary.
- `MIN_VERSION` The minimum version of the target binary.
- `PKL_FILE` The path to the pickle file. (e.g. /path/to/sig.pkl)

```
ida/run.sh /path/to/IDB
```

## TODO

- [ ] add support for global variables/constants
- [ ] byte pattern matching
- [ ] use arg count to assist in identifying anchor caller (as arg position/register)

## License

MIT Copyright (c) 2024 blacktop