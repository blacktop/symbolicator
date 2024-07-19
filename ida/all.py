#!/usr/bin/env python3

import os
import subprocess

config = [
    {
        "target": "com.apple.kernel",
        "sig": "kernel/20/xnu.json",
        "max": "20.6.0",
        "min": "20.0.0",
        "i64": "/Library/Developer/KDKs/KDK_11.7.9_20G1426.kdk/System/Library/Kernels/kernel.release.t8101",
    },
    {
        "target": "com.apple.kernel",
        "sig": "kernel/21/xnu.json",
        "max": "21.6.0",
        "min": "21.0.0",
        "i64": "/Library/Developer/KDKs/KDK_12.5_21G72.kdk/System/Library/Kernels/kernel.release.t8110",
    },
    {
        "target": "com.apple.kernel",
        "sig": "kernel/22/xnu.json",
        "max": "22.6.0",
        "min": "22.0.0",
        "i64": "/Library/Developer/KDKs/KDK_13.6.7_22G720.kdk/System/Library/Kernels/kernel.release.t8122",
    },
    {
        "target": "com.apple.kernel",
        "sig": "kernel/23/xnu.json",
        "max": "23.5.0",
        "min": "23.0.0",
        "i64": "/Library/Developer/KDKs/KDK_14.5_23F79.kdk/System/Library/Kernels/kernel.release.t8122",
    },
    {
        "target": "com.apple.kernel",
        "sig": "kernel/24/xnu.json",
        "max": "24.0.0",
        "min": "24.0.0",
        "i64": "/Library/Developer/KDKs/KDK_15.0_24A5289h.kdk/System/Library/Kernels/kernel.release.t8122",
    },
]

for c in config:
    os.environ["TARGET"] = c["target"]
    os.environ["JSON_FILE"] = c["sig"]
    os.environ["MAX_VERSION"] = c["max"]
    os.environ["MIN_VERSION"] = c["min"]
    subprocess.run(["ida/run.sh", "kernel", c["i64"]])

print("✅ Done")
