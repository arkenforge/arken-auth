#!/usr/bin/env python3
"""Build the Rust native library for arken-auth-py."""

import os
import platform
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RUST_DIR = os.path.join(HERE, "rust")
BIN_DIR = os.path.join(HERE, "arken_auth", "bin")


def lib_name():
    ext = {"Windows": ".dll", "Darwin": ".dylib"}.get(platform.system(), ".so")
    prefix = "" if platform.system() == "Windows" else "lib"
    return f"{prefix}arken_core{ext}"


def check_cargo():
    return shutil.which("cargo") is not None


if __name__ == "__main__":
    print("[arken-auth] Building native library...")

    if not check_cargo():
        print("ERROR: Rust toolchain not found.\nInstall from https://rustup.rs")
        sys.exit(1)

    result = subprocess.run(
        ["cargo", "build", "--release"],
        cwd=RUST_DIR,
    )
    if result.returncode != 0:
        print("ERROR: Rust build failed.")
        sys.exit(1)

    os.makedirs(BIN_DIR, exist_ok=True)
    src = os.path.join(RUST_DIR, "target", "release", lib_name())
    dst = os.path.join(BIN_DIR, lib_name())
    shutil.copy2(src, dst)

    print(f"[arken-auth] Built → arken_auth/bin/{lib_name()}")
