<p align="center">
  <a href="https://github.com/blacktop/symbolicator"><img alt="Symbolicator Logo" src="https://github.com/blacktop/symbolicator/blob/main/docs/logo.png?raw=true" height="300" /></a>
  <!-- <h1 align="center">symbolicator</h1> -->
  <h3><p align="center"><code>ipsw</code> symbolication signatures</p></h3>
  <!-- <p align="center">
    <a href="https://github.com/blacktop/symbolicator/releases/latest" alt="Downloads">
          <img src="https://img.shields.io/github/downloads/blacktop/symbolicator/total.svg" /></a>
    <a href="https://github.com/blacktop/symbolicator/releases" alt="GitHub Release">
          <img src="https://img.shields.io/github/release/blacktop/symbolicator.svg" /></a>
    <a href="http://doge.mit-license.org" alt="LICENSE">
          <img src="https://img.shields.io/:license-mit-blue.svg" /></a>
</p> -->
<br>

## What 🤔

This repo contains the [ipsw](https://github.com/blacktop/ipsw) symbolication signature files.

## How Good 📈

Currently we are sitting at `63.85%` on **xnu**

## Getting Started 🚀

Get the signatures

```bash
git clone https://github.com/blacktop/symbolicator.git
```

Symbolicate a kernelcache with [ipsw](https://github.com/blacktop/ipsw)

```bash
ipsw kernel sym kernelcache --json --signatures /path/to/symbolicator-repo/kernel
```

Install IDA Plugin

```bash
plugins/ida/install.sh
```

Now you can apply the symbols to you kernelcache in IDA by pressing `Alt+F8`

![ida-pluging](plugins/ida/docs/ida.png)

_The first time the IDB if loaded, the plugin will attempt to automatically load the symbols file (This is verified
using an indication file with the suffix `.symbols_loaded`)_

## Plugins 🔌

Supported Plugins/Scripts

- [Binary Ninja](plugins/binja)
- [Ghidra](plugins/ghidra)
- [IDA Pro](plugins/ida)
- [radare2](https://github.com/radareorg/radare2/blob/master/scripts/ipsw-kernel-symbolicate.r2.js)

## Generate NEW signatures

You can set these ENV VARS to control the the outputed signature's metadata

- `TARGET` The target binary. (e.g. com.apple.driver.AppleMobileFileIntegrity)
- `MAX_VERSION` The maximum version of the target darwin.
- `MIN_VERSION` The minimum version of the target darwin.
- `JSON_FILE` The path to the JSON file. (e.g. /path/to/sig.json)

To generate signatures for `xnu`

```bash
scripts/run.sh --kernel '/path/to/KDK/kernel'
```

To generate signatures for a `kext`

```bash
scripts/run.sh --kext '/path/to/KDK/kext'
```

## TODO

- [ ] add support for global variables/constants
- [ ] byte pattern matching
- [ ] use arg count to assist in identifying anchor caller (as arg position/register)

## Credit

Idea was originally inspired by Jonathan Levin's [disarm](https://newosxbook.com/tools/disarm.html) 'matchers' file.

## License

MIT Copyright (c) 2024 blacktop