#!/usr/bin/env python3

import os
import subprocess
from pathlib import Path

config = [
    {
        "target": "com.apple.kernel",
        "pkl": "kernel/20/xnu.json",
        "max": "20.6.0",
        "min": "20.0.0",
        "i64": str(Path.home() / "RE/macOS11.7.9/kernel.release.t8101.i64"),
    },
    {
        "target": "com.apple.kernel",
        "pkl": "kernel/21/xnu.json",
        "max": "21.6.0",
        "min": "21.0.0",
        "i64": str(Path.home() / "RE/macOS12.7.4/kernel.release.t8110.i64"),
    },
    {
        "target": "com.apple.kernel",
        "pkl": "kernel/22/xnu.json",
        "max": "22.6.0",
        "min": "22.0.0",
        "i64": str(Path.home() / "RE/macOS13.6.7/kernel.release.t8122.i64"),
    },
    {
        "target": "com.apple.kernel",
        "pkl": "kernel/23/xnu.json",
        "max": "23.5.0",
        "min": "23.0.0",
        "i64": str(Path.home() / "RE/macOS14.5/kernel.release.t8122.i64"),
    },
    {
        "target": "com.apple.kernel",
        "pkl": "kernel/24/xnu.json",
        "max": "24.0.0",
        "min": "24.0.0",
        "i64": str(Path.home() / "RE/macOS15b3/kernel.release.t8122.i64"),
    },
]

for c in config:
    os.environ["TARGET"] = c["target"]
    os.environ["PKL_FILE"] = c["pkl"]
    os.environ["MAX_VERSION"] = c["max"]
    os.environ["MIN_VERSION"] = c["min"]
    subprocess.run(["ida/run.sh", c["i64"]])
