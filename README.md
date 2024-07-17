# symbolicator

> `ipsw` symbolication signatures

## What 🤔

This repo contain's `ipsw`'s symbolication signature format as well as all generated signature [pkl](https://github.com/apple/pkl) files.

## Getting Started

Get the signatures

```bash
git clone https://github.com/blacktop/symbolicator.git
```

Symbolicate a kernelcache

```bash
ipsw kernel sym KC --signatures /path/to/symbolicator-repo/kernel
```

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

## License

MIT Copyright (c) 2024 blacktop