#!/usr/bin/env python3

import os
import subprocess


kexts = [
    {
        "target": "com.apple.driver.AppleMobileFileIntegrity",
        "sig": "kernel/24/amfi.json",
        "max": "24.0.0",
        "min": "24.0.0",
        "i64": "/Library/Developer/KDKs/KDK_15.0_24A5289h.kdk/System/Library/Extensions/AppleMobileFileIntegrity.kext/Contents/MacOS/AppleMobileFileIntegrity",
    },
    {
        "target": "com.apple.security.sandbox",
        "sig": "kernel/24/sandbox.json",
        "max": "24.0.0",
        "min": "24.0.0",
        "i64": "/Library/Developer/KDKs/KDK_15.0_24A5289h.kdk/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox",
    },
    {
        "target": "com.apple.kec.corecrypto",
        "sig": "kernel/24/corecrypto.json",
        "max": "24.0.0",
        "min": "24.0.0",
        "i64": "/Library/Developer/KDKs/KDK_15.0_24A5289h.kdk/System/Library/Extensions/corecrypto.kext/Contents/MacOS/corecrypto",
    },
    {
        "target": "com.apple.driver.AppleLockdownMode",
        "sig": "kernel/24/ldm.json",
        "max": "24.0.0",
        "min": "24.0.0",
        "i64": "/Library/Developer/KDKs/KDK_15.0_24A5289h.kdk/System/Library/Extensions/AppleLockdownMode.kext/Contents/MacOS/AppleLockdownMode",
    },
    {
        "target": "com.apple.driver.ApplePMGR",
        "sig": "kernel/24/pmgr.json",
        "max": "24.0.0",
        "min": "24.0.0",
        "i64": "/Library/Developer/KDKs/KDK_15.0_24A5289h.kdk/System/Library/Extensions/ApplePMGR.kext/Contents/MacOS/ApplePMGR",
    },
    {
        "target": "com.apple.filesystems.apfs",
        "sig": "kernel/24/apfs.json",
        "max": "24.0.0",
        "min": "24.0.0",
        "i64": "/Library/Developer/KDKs/KDK_15.0_24A5289h.kdk/System/Library/Extensions/apfs.kext/Contents/MacOS/apfs",
    },
    {
        "target": "com.apple.kec.AppleEncryptedArchive",
        "sig": "kernel/24/aea.json",
        "max": "24.0.0",
        "min": "24.0.0",
        "i64": "/Library/Developer/KDKs/KDK_15.0_24A5289h.kdk/System/Library/Extensions/AppleEncryptedArchive.kext/Contents/MacOS/AppleEncryptedArchive",
    },
]

kernels = [
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

if __name__ == "__main__":
    if os.getenv("DO_KEXTS"):
        for x in kexts:
            os.environ["TARGET"] = x["target"]
            os.environ["JSON_FILE"] = x["sig"]
            os.environ["MAX_VERSION"] = x["max"]
            os.environ["MIN_VERSION"] = x["min"]
            subprocess.run(["ida/run.sh", "--kext", x["i64"]])
    if os.getenv("DO_KERNELS"):
        for k in kernels:
            os.environ["TARGET"] = k["target"]
            os.environ["JSON_FILE"] = k["sig"]
            os.environ["MAX_VERSION"] = k["max"]
            os.environ["MIN_VERSION"] = k["min"]
            subprocess.run(["ida/run.sh", "--kernel", k["i64"]])

    print("✅ Done")
