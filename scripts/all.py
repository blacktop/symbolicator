#!/usr/bin/env python3

import os
import pathlib
import plistlib
import subprocess

kernels = [
    # {
    #     "target": "com.apple.kernel",
    #     "folder": "kernel/19",
    #     "max": "19.6.0",
    #     "min": "19.0.0",
    #     "kernel": "/Library/Developer/KDKs/KDK_10.15.7_19H1824.kdk/System/Library/Kernels/kernel",
    #     "extensions": "/Library/Developer/KDKs/KDK_10.15.7_19H1824.kdk/System/Library/Extensions/",
    #     "skip_list": [],
    # },
    # {
    #     "target": "com.apple.kernel",
    #     "folder": "kernel/20",
    #     "max": "20.6.0",
    #     "min": "20.0.0",
    #     "kernel": "/Library/Developer/KDKs/KDK_11.7.9_20G1426.kdk/System/Library/Kernels/kernel.release.t8101",
    #     "extensions": "/Library/Developer/KDKs/KDK_11.7.9_20G1426.kdk/System/Library/Extensions",
    #     "skip_list": [],
    # },
    # {
    #     "target": "com.apple.kernel",
    #     "folder": "kernel/21",
    #     "max": "21.6.0",
    #     "min": "21.0.0",
    #     "kernel": "/Library/Developer/KDKs/KDK_12.5_21G72.kdk/System/Library/Kernels/kernel.release.t8110",
    #     "extensions": "/Library/Developer/KDKs/KDK_12.5_21G72.kdk/System/Library/Extensions",
    #     "skip_list": [],
    # },
    # {
    #     "target": "com.apple.kernel",
    #     "folder": "kernel/22",
    #     "max": "22.6.0",
    #     "min": "22.0.0",
    #     "kernel": "/Library/Developer/KDKs/KDK_13.6.7_22G720.kdk/System/Library/Kernels/kernel.release.t8122",
    #     "extensions": "/Library/Developer/KDKs/KDK_13.6.7_22G720.kdk/System/Library/Extensions",
    #     "skip_list": [],
    # },
    # {
    #     "target": "com.apple.kernel",
    #     "folder": "kernel/23",
    #     "max": "23.6.0",
    #     "min": "23.0.0",
    #     "kernel": "/Library/Developer/KDKs/KDK_14.6.1_23G93.kdk/System/Library/Kernels/kernel.release.t8122",
    #     "extensions": "/Library/Developer/KDKs/KDK_14.6.1_23G93.kdk/System/Library/Extensions",
    #     "skip_list": [],
    # },
    # {
    #     "target": "com.apple.kernel",
    #     "folder": "kernel/24.0",
    #     "max": "24.1.0",
    #     "min": "24.0.0",
    #     "kernel": "/Library/Developer/KDKs/KDK_15.0_24A335.kdk/System/Library/Kernels/kernel.release.t8122",
    #     "extensions": "/Library/Developer/KDKs/KDK_15.0_24A335.kdk/System/Library/Extensions",
    #     "skip_list": [],
    # },
    # {
    #     "target": "com.apple.kernel",
    #     "folder": "kernel/24.1",
    #     "max": "24.2.0",
    #     "min": "24.1.0",
    #     "kernel": "/Library/Developer/KDKs/KDK_15.1.1_24B91.kdk/System/Library/Kernels/kernel.release.t6030",
    #     "extensions": "/Library/Developer/KDKs/KDK_15.1.1_24B91.kdk/System/Library/Extensions",
    #     "skip_list": [],
    # },
    # {
    #     "target": "com.apple.kernel",
    #     "folder": "kernel/24.2",
    #     "max": "24.3.0",
    #     "min": "24.2.0",
    #     "kernel": "/Library/Developer/KDKs/KDK_15.2_24C101.kdk/System/Library/Kernels/kernel.release.t8132",
    #     "extensions": "/Library/Developer/KDKs/KDK_15.2_24C101.kdk/System/Library/Extensions",
    #     "skip_list": [],
    # },
    # {
    #     "target": "com.apple.kernel",
    #     "folder": "kernel/24.3",
    #     "max": "24.4.0",
    #     "min": "24.3.0",
    #     "kernel": "/Library/Developer/KDKs/KDK_15.3.1_24D70.kdk/System/Library/Kernels/kernel.release.t8132",
    #     "extensions": "/Library/Developer/KDKs/KDK_15.3.1_24D70.kdk/System/Library/Extensions",
    #     "skip_list": [],
    # },
    # {
    #     "target": "com.apple.kernel",
    #     "folder": "kernel/24.4",
    #     "max": "24.5.0",
    #     "min": "24.4.0",
    #     "kernel": "/Library/Developer/KDKs/KDK_15.4_24E247.kdk/System/Library/Kernels/kernel.release.t8132",
    #     "extensions": "/Library/Developer/KDKs/KDK_15.4_24E247.kdk/System/Library/Extensions",
    #     "skip_list": [],
    # },
    # {
    #     "target": "com.apple.kernel",
    #     "folder": "kernel/24.5",
    #     "max": "24.6.0",
    #     "min": "24.5.0",
    #     "kernel": "/Library/Developer/KDKs/KDK_15.5_24F74.kdk/System/Library/Kernels/kernel.release.t8132",
    #     "extensions": "/Library/Developer/KDKs/KDK_15.5_24F74.kdk/System/Library/Extensions",
    #     "skip_list": [],
    # },
    # {
    #     "target": "com.apple.kernel",
    #     "folder": "kernel/25.0",
    #     "max": "25.1.0",
    #     "min": "25.0.0",
    #     "kernel": "/Library/Developer/KDKs/KDK_26.0_25A353.kdk/System/Library/Kernels/kernel.release.t8132",
    #     "extensions": "/Library/Developer/KDKs/KDK_26.0_25A353.kdk/System/Library/Extensions",
    #     "skip_list": [],
    # },
    # {
    #     "target": "com.apple.kernel",
    #     "folder": "kernel/25.1",
    #     "max": "25.2.0",
    #     "min": "25.1.0",
    #     "kernel": "/Library/Developer/KDKs/KDK_26.1_25B5062e.kdk/System/Library/Kernels/kernel.release.t8132",
    #     "extensions": "/Library/Developer/KDKs/KDK_26.1_25B5062e.kdk/System/Library/Extensions",
    #     "skip_list": [],
    # },
    # {
    #     "target": "com.apple.kernel",
    #     "folder": "kernel/25.2",
    #     "max": "25.3.0",
    #     "min": "25.2.0",
    #     "kernel": "/Library/Developer/KDKs/KDK_26.2_25C56.kdk/System/Library/Kernels/kernel.release.t8142",
    #     "extensions": "/Library/Developer/KDKs/KDK_26.2_25C56.kdk/System/Library/Extensions",
    #     "skip_list": [],
    # },
    # {
    #     "target": "com.apple.kernel",
    #     "folder": "kernel/25.3",
    #     "max": "25.4.0",
    #     "min": "25.3.0",
    #     "kernel": "/Library/Developer/KDKs/KDK_26.3.1_25D2128.kdk/System/Library/Kernels/kernel.release.t8142",
    #     "extensions": "/Library/Developer/KDKs/KDK_26.3.1_25D2128.kdk/System/Library/Extensions",
    #     "skip_list": [],
    # },
    {
        "target": "com.apple.kernel",
        "folder": "kernel/25.4",
        "max": "25.5.0",
        "min": "25.4.0",
        "kernel": "/Library/Developer/KDKs/KDK_26.4_25E246.kdk/System/Library/Kernels/kernel.release.t8142",
        "extensions": "/Library/Developer/KDKs/KDK_26.4_25E246.kdk/System/Library/Extensions",
        "skip_list": [],
    },
]


def is_macho(filepath):
    """Check if a file is a Mach-O binary by reading its magic bytes."""
    MACHO_MAGICS = {
        b"\xfe\xed\xfa\xce",  # MH_MAGIC (32-bit)
        b"\xce\xfa\xed\xfe",  # MH_CIGAM (32-bit, swapped)
        b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64 (64-bit)
        b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64 (64-bit, swapped)
        b"\xca\xfe\xba\xbe",  # FAT_MAGIC (universal)
        b"\xbe\xba\xfe\xca",  # FAT_CIGAM (universal, swapped)
    }
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
            return magic in MACHO_MAGICS
    except (IOError, OSError):
        return False


def build_kext_index(directory):
    """Build a list of KDK bundle targets by scanning bundle metadata."""
    targets = []
    used_output_names = set()
    extensions_path = pathlib.Path(directory)

    for info_path in sorted(extensions_path.rglob("Contents/Info.plist")):
        bundle_path = info_path.parents[1]
        bundle_path_str = str(bundle_path)
        if ".kext" not in bundle_path_str:
            continue

        try:
            info = plistlib.loads(info_path.read_bytes())
        except (OSError, plistlib.InvalidFileException):
            continue

        bundle_id = info.get("CFBundleIdentifier")
        executable = info.get("CFBundleExecutable")
        if not bundle_id or not executable:
            continue

        binary_path = bundle_path / "Contents" / "MacOS" / executable
        if executable.lower().endswith("_kasan") or not is_macho(binary_path):
            continue

        output_name = bundle_id.rsplit(".", 1)[-1]
        if output_name == "kext":
            output_name = bundle_id.rsplit(".", 2)[-2]
        if output_name in used_output_names:
            output_name = bundle_id
        used_output_names.add(output_name)

        targets.append(
            {
                "bundle_id": bundle_id,
                "binary_path": str(binary_path),
                "executable": executable,
                "output_name": output_name,
            }
        )

    targets.sort(key=lambda item: item["bundle_id"])
    return targets


if __name__ == "__main__":
    if os.getenv("DO_KEXTS"):
        for k in kernels:
            kext_targets = build_kext_index(k["extensions"])
            print(
                f"🔎 discovered {len(kext_targets)} KDK extension targets in {k['extensions']}"
            )
            for target in kext_targets:
                executable = target["executable"]
                if (
                    executable in k["skip_list"]
                    or target["output_name"] in k["skip_list"]
                ):
                    continue
                os.environ["TARGET"] = target["bundle_id"]
                folder = str(k["folder"])
                os.makedirs(f"{folder}/kexts", 0o750, exist_ok=True)
                json_file = f"{folder}/kexts/{target['output_name']}.json"
                os.environ["JSON_FILE"] = json_file
                if os.path.exists(json_file):
                    print(f"⏭️  {json_file} already exists (overwriting ✍️ )")
                os.environ["MAX_VERSION"] = str(k["max"])
                os.environ["MIN_VERSION"] = str(k["min"])
                result = subprocess.run(
                    [
                        "scripts/run.sh",
                        "--kext",
                        target["binary_path"],
                    ]
                )
                if result.returncode != 0:
                    print(
                        f"❌ scripts/run.sh failed for {target['bundle_id']} "
                        f"({target['binary_path']}, exit code: {result.returncode})"
                    )

    if os.getenv("DO_KERNELS"):
        for k in kernels:
            os.environ["TARGET"] = str(k["target"])
            folder = str(k["folder"])
            os.makedirs(folder, 0o750, exist_ok=True)
            os.environ["JSON_FILE"] = f"{folder}/xnu.json"
            os.environ["MAX_VERSION"] = str(k["max"])
            os.environ["MIN_VERSION"] = str(k["min"])
            result = subprocess.run(["scripts/run.sh", "--kernel", str(k["kernel"])])
            if result.returncode != 0:
                print(
                    f"❌ scripts/run.sh failed for kernel {k['kernel']} (exit code: {result.returncode})"
                )

    print("✅ Done")
