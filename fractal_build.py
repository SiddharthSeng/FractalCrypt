#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
+==============================================================================+
|   fractal_build.py — PyInstaller Build Script for FractalCrypt               |
|                                                                              |
|   Bundles fractal_gui.py, fractal_encrypt_v2.py, and fractal_encrypt.py     |
|   into a single standalone executable (no Python installation required).     |
|                                                                              |
|   Output                                                                     |
|   ──────                                                                     |
|   Windows  → dist/FractalCrypt.exe                                           |
|   macOS    → dist/FractalCrypt  (or dist/FractalCrypt.app if --windowed)    |
|   Linux    → dist/FractalCrypt                                               |
|                                                                              |
|   Usage                                                                      |
|   ─────                                                                      |
|   python fractal_build.py                  # standard build                  |
|   python fractal_build.py --console        # keep console window             |
|   python fractal_build.py --clean          # delete previous build first     |
|   python fractal_build.py --no-pillow      # skip Pillow hidden imports      |
+==============================================================================+
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

APP_NAME    = "FractalCrypt"
ENTRY_POINT = "fractal_gui.py"
DATA_FILES  = ["fractal_encrypt.py", "fractal_encrypt_v2.py"]

HIDDEN_IMPORTS = [
    "PIL",
    "PIL.Image",
    "PIL.ImageTk",
    "PIL.ImageDraw",
    "PIL.ImageFont",
    "hashlib",
    "hmac",
    "zipfile",
    "tempfile",
    "threading",
    "tkinter",
    "tkinter.filedialog",
    "tkinter.messagebox",
    "tkinter.ttk",
    "tkinterdnd2",
]

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _banner(text: str) -> None:
    """Print a formatted banner line to stdout."""
    width = 60
    print()
    print("+" + "=" * width + "+")
    print(f"|  {text:<{width - 2}}|")
    print("+" + "=" * width + "+")
    print()


def _run(cmd: list, check: bool = True) -> subprocess.CompletedProcess:
    """
    Run a subprocess command and stream output in real-time.

    Parameters
    ----------
    cmd : list[str]
        Command and arguments.
    check : bool
        If True, raise CalledProcessError on non-zero exit.

    Returns
    -------
    subprocess.CompletedProcess
    """
    print(f"  $ {' '.join(cmd)}")
    result = subprocess.run(cmd, check=check)
    return result


def _python() -> str:
    """
    Return the path to the current Python executable.

    Returns
    -------
    str
        Absolute path to python interpreter.
    """
    return sys.executable


def _check_pyinstaller() -> bool:
    """
    Check whether PyInstaller is importable.

    Returns
    -------
    bool
        True if PyInstaller is installed.
    """
    try:
        import importlib
        importlib.import_module("PyInstaller")
        return True
    except ImportError:
        return False


def _install_pyinstaller() -> None:
    """
    Install PyInstaller using pip into the current Python environment.

    Raises
    ------
    SystemExit
        If installation fails.
    """
    print("  [!] PyInstaller not found — installing…")
    try:
        _run([_python(), "-m", "pip", "install", "--upgrade", "pyinstaller"])
        print("  [✓] PyInstaller installed successfully.")
    except subprocess.CalledProcessError as exc:
        print(f"\n  [✗] Failed to install PyInstaller: {exc}", file=sys.stderr)
        print("       Try manually:  pip install pyinstaller", file=sys.stderr)
        sys.exit(1)


def _add_data_sep() -> str:
    """
    Return the platform-specific path separator for PyInstaller --add-data.

    Returns
    -------
    str
        ";" on Windows, ":" on macOS/Linux.
    """
    return ";" if platform.system() == "Windows" else ":"


def _validate_sources() -> None:
    """
    Verify that all required source files exist in the current directory.

    Raises
    ------
    SystemExit
        If any required file is missing.
    """
    missing = []
    for f in [ENTRY_POINT] + DATA_FILES:
        if not os.path.isfile(f):
            missing.append(f)
    if missing:
        print(f"\n  [✗] Missing source files: {missing}", file=sys.stderr)
        print("       Run this script from the project root directory.",
              file=sys.stderr)
        sys.exit(1)


def _clean_previous() -> None:
    """Remove previous build/ and dist/ directories and .spec file."""
    for path in ["build", "dist", f"{APP_NAME}.spec"]:
        if os.path.exists(path):
            if os.path.isdir(path):
                shutil.rmtree(path)
                print(f"  [✓] Removed directory: {path}")
            else:
                os.remove(path)
                print(f"  [✓] Removed file: {path}")


def _build(windowed: bool = True, include_pillow: bool = True) -> str:
    """
    Invoke PyInstaller to build the standalone executable.

    Parameters
    ----------
    windowed : bool
        If True, use --windowed (no console window).  Default True.
    include_pillow : bool
        If True, add Pillow-related hidden imports.

    Returns
    -------
    str
        Path to the produced executable.
    """
    sep = _add_data_sep()

    cmd = [
        _python(), "-m", "PyInstaller",
        ENTRY_POINT,
        "--onefile",
        f"--name={APP_NAME}",
        "--noconfirm",
    ]

    if windowed:
        cmd.append("--windowed")

    # Add data files (fractal_encrypt.py and fractal_encrypt_v2.py)
    for data_file in DATA_FILES:
        cmd.append(f"--add-data={data_file}{sep}.")

    # Hidden imports
    imports = HIDDEN_IMPORTS if include_pillow else [
        h for h in HIDDEN_IMPORTS
        if not h.startswith("PIL")
    ]
    for hidden in imports:
        cmd.append(f"--hidden-import={hidden}")

    # Run PyInstaller
    try:
        _run(cmd)
    except subprocess.CalledProcessError as exc:
        print(f"\n  [✗] PyInstaller failed (exit code {exc.returncode}).",
              file=sys.stderr)
        sys.exit(1)

    # Locate the output executable
    exe_path = _locate_exe()
    return exe_path


def _locate_exe() -> str:
    """
    Find the generated executable in the dist/ directory.

    Returns
    -------
    str
        Absolute path to the executable.

    Raises
    ------
    SystemExit
        If no executable is found.
    """
    system = platform.system()
    dist_dir = os.path.join(os.getcwd(), "dist")

    if system == "Windows":
        candidate = os.path.join(dist_dir, f"{APP_NAME}.exe")
    elif system == "Darwin":
        # macOS: either .app bundle or plain binary
        app_bundle = os.path.join(dist_dir, f"{APP_NAME}.app")
        candidate  = app_bundle if os.path.exists(app_bundle) else \
                     os.path.join(dist_dir, APP_NAME)
    else:
        candidate = os.path.join(dist_dir, APP_NAME)

    if os.path.exists(candidate):
        return candidate

    # Fallback: search dist/ for anything matching the name
    if os.path.isdir(dist_dir):
        for entry in os.listdir(dist_dir):
            if APP_NAME.lower() in entry.lower():
                return os.path.join(dist_dir, entry)

    print(f"\n  [✗] Could not locate output executable in: {dist_dir}",
          file=sys.stderr)
    sys.exit(1)


def _print_summary(exe_path: str) -> None:
    """
    Print the build summary with the output executable path and size.

    Parameters
    ----------
    exe_path : str
        Path to the produced executable.
    """
    size_bytes = os.path.getsize(exe_path) if os.path.isfile(exe_path) else 0
    size_mb    = size_bytes / (1024 * 1024)

    _banner("BUILD COMPLETE")
    print(f"  Executable  : {exe_path}")
    if size_bytes:
        print(f"  Size        : {size_mb:.1f} MB  ({size_bytes:,} bytes)")
    print(f"  Platform    : {platform.system()} {platform.machine()}")
    print(f"  Python      : {sys.version.split()[0]}")
    print()
    print("  To run:")
    if platform.system() == "Windows":
        print(f"    {exe_path}")
    else:
        print(f"    ./{exe_path}")
    print()
    print("  ⚠  Distribute only the single file in dist/")
    print("     fractal_encrypt.py and fractal_encrypt_v2.py")
    print("     are bundled inside — do not distribute separately.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """
    Entry point for the build script.

    Parses command-line arguments, ensures PyInstaller is available,
    validates source files, and invokes the PyInstaller build.
    """
    parser = argparse.ArgumentParser(
        prog="fractal_build",
        description="Build FractalCrypt into a standalone executable.",
    )
    parser.add_argument(
        "--console", action="store_true",
        help="Keep the console window open (useful for debugging).",
    )
    parser.add_argument(
        "--clean", action="store_true",
        help="Delete previous build/ and dist/ directories before building.",
    )
    parser.add_argument(
        "--no-pillow", action="store_true",
        help="Skip Pillow hidden imports (Key Visualizer will be disabled).",
    )
    args = parser.parse_args()

    _banner(f"FractalCrypt Build Script  —  {platform.system()}")

    # ── Step 1: validate source files ─────────────────────────────────────────
    print("[1/4]  Validating source files…")
    _validate_sources()
    print(f"  [✓]  {ENTRY_POINT}  found")
    for df in DATA_FILES:
        print(f"  [✓]  {df}  found")
    print()

    # ── Step 2: ensure PyInstaller ────────────────────────────────────────────
    print("[2/4]  Checking PyInstaller…")
    if not _check_pyinstaller():
        _install_pyinstaller()
    else:
        print("  [✓]  PyInstaller is installed.")
    print()

    # ── Step 3: clean (optional) ──────────────────────────────────────────────
    if args.clean:
        print("[3/4]  Cleaning previous build artifacts…")
        _clean_previous()
    else:
        print("[3/4]  Skipping clean  (use --clean to remove previous build).")
    print()

    # ── Step 4: build ─────────────────────────────────────────────────────────
    print("[4/4]  Invoking PyInstaller…")
    windowed       = not args.console
    include_pillow = not args.no_pillow

    exe_path = _build(windowed=windowed, include_pillow=include_pillow)

    # ── Summary ───────────────────────────────────────────────────────────────
    _print_summary(exe_path)


if __name__ == "__main__":
    main()
