#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
+==============================================================================+
|   🔮  FractalCrypt — Fractal File Encryption GUI  v4.0                       |
|   fractal_gui.py  —  Tkinter desktop application + CLI fallback              |
|                                                                              |
|   Features                                                                   |
|   ────────                                                                   |
|   • Multi-file and folder encryption/decryption                              |
|   • PBKDF2 key stretching (200,000 iterations) via fractal_encrypt_v2       |
|   • ASCII Armor mode (.fractal.asc with PGP-style header/footer)            |
|   • Drag & Drop file support (tkinterdnd2, graceful fallback)                |
|   • Fractal Key Visualizer (Mandelbrot + Julia rendered to canvas)           |
|   • Key Fingerprint PNG Export (800x400 composite with metadata)             |
|   • Keystream Randomness Histogram (chi-squared, Shannon entropy)            |
|   • Secure Notes tab — encrypt/decrypt text notes in-app                     |
|   • Secure File Shredder — DoD 5220.22-M 3-pass overwrite + cooldown        |
|   • Dual mode: GUI (default) + CLI fallback (encrypt/decrypt/shred/analyze)  |
|   • Dark "deep-space fractal" aesthetic                                      |
|                                                                              |
|   Dependencies                                                               |
|   ────────────                                                                |
|   • tkinter     (stdlib)                                                     |
|   • Pillow/PIL  (optional — Key Visualizer + PNG Export)                     |
|   • tkinterdnd2 (optional — drag & drop)                                     |
|   • fractal_encrypt_v2  (local — must be in same directory)                 |
|                                                                              |
|   Run:  python fractal_gui.py                    ← GUI mode                 |
|         python fractal_gui.py encrypt ...        ← CLI mode                 |
+==============================================================================+
"""

# ─────────────────────────────────────────────────────────────────────────────
# STANDARD LIBRARY IMPORTS
# ─────────────────────────────────────────────────────────────────────────────

import base64
import datetime
import hashlib
import io
import math
import os
import shutil
import struct
import sys
import tempfile
import threading
import time
import zipfile

# ─────────────────────────────────────────────────────────────────────────────
# CLI DETECTION — guard all Tkinter imports behind this flag
# ─────────────────────────────────────────────────────────────────────────────

CLI_TRIGGERS = ["encrypt", "decrypt", "shred", "analyze", "--help", "-h"]
_CLI_MODE = len(sys.argv) > 1 and sys.argv[1] in CLI_TRIGGERS

if not _CLI_MODE:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    # ── Optional: Pillow ──────────────────────────────────────────────────────
    try:
        from PIL import Image, ImageTk, ImageDraw, ImageFont
        PIL_AVAILABLE = True
    except ImportError:
        PIL_AVAILABLE = False

    # ── Optional: tkinterdnd2 ─────────────────────────────────────────────────
    try:
        from tkinterdnd2 import TkinterDnD, DND_FILES
        DND_AVAILABLE = True
    except ImportError:
        DND_AVAILABLE = False
else:
    PIL_AVAILABLE = False
    DND_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# LOCAL IMPORT
# ─────────────────────────────────────────────────────────────────────────────

try:
    from fractal_encrypt_v2 import FractalCipherV2, FractalKeyEngine, stretch_password
    from fractal_encrypt import MAGIC_HEADER
except ImportError as _e:
    print(f"[ERROR] Cannot import fractal_encrypt_v2: {_e}", file=sys.stderr)
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# DESIGN SYSTEM — COLOUR PALETTE & FONTS
# ─────────────────────────────────────────────────────────────────────────────

BG_DARK   = "#0d0d1a"   # window background
BG_PANEL  = "#12122a"   # notebook / tab background
BG_CARD   = "#1a1a3a"   # card / widget panel background
ACCENT    = "#00ffcc"   # electric teal  (primary action)
ACCENT2   = "#ff00aa"   # hot magenta    (secondary action)
TEXT      = "#e0e0ff"   # soft lavender-white text
TEXT_DIM  = "#6666aa"   # de-emphasised text
SUCCESS   = "#00ff88"   # success green
ERROR     = "#ff4466"   # error red
WARNING   = "#ffaa00"   # warning amber
BORDER    = "#2a2a5a"   # panel borders
NOTE_HASH = "#7755bb"   # note-tab heading colour (dim purple)
SHRED_RED = "#ff4466"   # shredder danger colour
SHRED_BG  = "#2a0a0a"   # shredder warning banner background

FONT_MONO    = ("Consolas", 10)
FONT_MONO_SM = ("Consolas", 9)
FONT_MONO_LG = ("Consolas", 12)
FONT_MONO_XL = ("Consolas", 14, "bold")
FONT_LABEL   = ("Consolas", 10)
FONT_TITLE   = ("Consolas", 11, "bold")
FONT_NOTE    = ("Consolas", 11)

# ─────────────────────────────────────────────────────────────────────────────
# ASCII ARMOR HELPERS
# ─────────────────────────────────────────────────────────────────────────────

_ARMOR_BEGIN = "-----BEGIN FRACTAL ENCRYPTED MESSAGE-----"
_ARMOR_END   = "-----END FRACTAL ENCRYPTED MESSAGE-----"


def armor_encode(blob: bytes, salt: bytes) -> str:
    """
    Wrap encrypted binary blob in a PGP-style ASCII armor envelope.

    Parameters
    ----------
    blob : bytes
        Raw .fractal v2 binary data.
    salt : bytes
        The 16-byte salt used during encryption (hex in header).

    Returns
    -------
    str
        Armored text with BEGIN/END delimiters and base64-encoded body.
    """
    b64_data = base64.b64encode(blob).decode("ascii")
    lines    = [b64_data[i:i + 64] for i in range(0, len(b64_data), 64)]
    parts    = [
        _ARMOR_BEGIN,
        "Version: FractalCipher 2.0",
        f"Salt: {salt.hex()}",
        "",
        "\n".join(lines),
        _ARMOR_END,
    ]
    return "\n".join(parts)


def armor_decode(text: str) -> bytes:
    """
    Strip ASCII armor envelope and return raw binary blob.

    Parameters
    ----------
    text : str
        Armored text starting with ``-----BEGIN FRACTAL``.

    Returns
    -------
    bytes
        Decoded binary .fractal v2 data.

    Raises
    ------
    ValueError
        If armor delimiters are missing or base64 is malformed.
    """
    lines      = text.strip().splitlines()
    if not lines or not lines[0].startswith("-----BEGIN FRACTAL"):
        raise ValueError("Not a valid ASCII-armored FRACTAL file.")

    body_lines = []
    inside     = False
    for line in lines:
        if line.startswith("-----BEGIN"):
            inside = True
            continue
        if line.startswith("-----END"):
            break
        if inside and line and not line.startswith(("Version:", "Salt:")):
            body_lines.append(line)

    try:
        return base64.b64decode("".join(body_lines))
    except Exception as exc:
        raise ValueError(f"Base64 decode error: {exc}") from exc


def is_armored(path: str) -> bool:
    """
    Return True if file at `path` looks like ASCII-armored FRACTAL data.

    Parameters
    ----------
    path : str
        File path to inspect.

    Returns
    -------
    bool
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(64).lstrip().startswith("-----BEGIN FRACTAL")
    except OSError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# SECURE SHREDDER ENGINE  (no Tkinter — usable from CLI too)
# ─────────────────────────────────────────────────────────────────────────────

def shred_file(path: str, passes: int = 3,
               progress_cb=None, log_cb=None) -> None:
    """
    Securely overwrite and delete a file using a DoD 5220.22-M inspired
    multi-pass overwrite algorithm.

    Pass 1: all 0x00 bytes
    Pass 2: all 0xFF bytes
    Pass 3: os.urandom (cryptographically random)
    Additional passes (if passes > 3): alternate 0x00 / 0xFF / random

    Each pass flushes and fsyncs to disk.

    Parameters
    ----------
    path : str
        Absolute path to the file to shred.
    passes : int
        Number of overwrite passes (minimum 1, maximum 7).
    progress_cb : callable or None
        Called with (pass_number, total_passes, byte_fraction) periodically.
    log_cb : callable or None
        Called with a human-readable log string.

    Raises
    ------
    FileNotFoundError
        If ``path`` does not exist or is not a file.
    PermissionError
        If the file cannot be opened for writing.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File not found: {path!r}")

    passes = max(1, min(passes, 7))
    file_size = os.path.getsize(path)
    fname = os.path.basename(path)

    def _log(msg: str) -> None:
        if log_cb:
            log_cb(msg)

    for p in range(1, passes + 1):
        if p == 1:
            pattern_name = "zeros"
        elif p == 2:
            pattern_name = "ones"
        else:
            pattern_name = "random"

        _log(f"Shredding {fname} — Pass {p}/{passes} ({pattern_name})…")

        with open(path, "r+b") as fh:
            written = 0
            chunk_size = 65536

            while written < file_size:
                remaining = file_size - written
                size = min(chunk_size, remaining)

                if p == 1:
                    chunk = b"\x00" * size
                elif p == 2:
                    chunk = b"\xff" * size
                else:
                    chunk = os.urandom(size)

                fh.write(chunk)
                written += size

                if progress_cb and file_size > 0:
                    progress_cb(p, passes, written / file_size)

            fh.flush()
            os.fsync(fh.fileno())

    os.remove(path)

    if os.path.exists(path):
        raise RuntimeError(f"File still exists after shredding: {path!r}")

    _log(
        f"✅ {fname} permanently deleted "
        f"({passes} passes, {file_size / (1024*1024):.2f} MB)"
    )


# ─────────────────────────────────────────────────────────────────────────────
# TOOLTIP HELPER
# ─────────────────────────────────────────────────────────────────────────────

if not _CLI_MODE:
    class Tooltip:
        """Lightweight hover tooltip for any Tkinter widget."""

        def __init__(self, widget, text: str) -> None:
            self.widget = widget
            self.text   = text
            self._tip   = None
            widget.bind("<Enter>", self._show)
            widget.bind("<Leave>", self._hide)

        def _show(self, _event=None) -> None:
            if self._tip:
                return
            x = self.widget.winfo_rootx() + 20
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
            self._tip = tw = tk.Toplevel(self.widget)
            tw.wm_overrideredirect(True)
            tw.wm_geometry(f"+{x}+{y}")
            tk.Label(tw, text=self.text, bg="#1e1e3a", fg=TEXT,
                     font=FONT_MONO_SM, relief="flat", bd=1,
                     padx=8, pady=4, wraplength=300).pack()

        def _hide(self, _event=None) -> None:
            if self._tip:
                self._tip.destroy()
                self._tip = None


# ─────────────────────────────────────────────────────────────────────────────
# LOG CONSOLE WIDGET
# ─────────────────────────────────────────────────────────────────────────────

if not _CLI_MODE:
    class LogConsole(tk.Frame):
        """Scrollable, color-coded terminal-style log widget."""

        def __init__(self, parent, **kwargs) -> None:
            super().__init__(parent, bg=BG_DARK, **kwargs)
            self._text = tk.Text(
                self, bg="#080810", fg=TEXT, font=FONT_MONO_SM,
                state="disabled", relief="flat", bd=0, wrap="word",
                cursor="arrow", selectbackground=BG_CARD, insertbackground=ACCENT,
            )
            scroll = tk.Scrollbar(self, orient="vertical",
                                  command=self._text.yview, bg=BG_CARD)
            self._text.configure(yscrollcommand=scroll.set)
            scroll.pack(side="right", fill="y")
            self._text.pack(side="left", fill="both", expand=True)

            for tag, fg in [("info", TEXT_DIM), ("success", SUCCESS),
                            ("error", ERROR), ("warning", WARNING),
                            ("accent", ACCENT), ("accent2", ACCENT2)]:
                self._text.tag_configure(tag, foreground=fg)

        def _append(self, msg: str, tag: str) -> None:
            """Append a timestamped log line."""
            self._text.configure(state="normal")
            self._text.insert("end", f"[{time.strftime('%H:%M:%S')}] {msg}\n", tag)
            self._text.see("end")
            self._text.configure(state="disabled")

        def info(self, msg: str)    -> None: self._append(msg, "info")
        def success(self, msg: str) -> None: self._append(msg, "success")
        def error(self, msg: str)   -> None: self._append(msg, "error")
        def warning(self, msg: str) -> None: self._append(msg, "warning")
        def accent(self, msg: str)  -> None: self._append(msg, "accent")

        def clear(self) -> None:
            self._text.configure(state="normal")
            self._text.delete("1.0", "end")
            self._text.configure(state="disabled")


# ─────────────────────────────────────────────────────────────────────────────
# PASSWORD STRENGTH METER
# ─────────────────────────────────────────────────────────────────────────────

if not _CLI_MODE:
    class PasswordMeter(tk.Frame):
        """Visual password strength indicator with entropy bar and label."""

        _LEVELS = [
            (0,  20,  "#ff4466", "Weak"),
            (20, 40,  "#ff7722", "Fair"),
            (40, 60,  "#ffaa00", "Good"),
            (60, 80,  "#88dd00", "Strong"),
            (80, 101, "#00ff88", "Fortress"),
        ]

        def __init__(self, parent, **kwargs) -> None:
            super().__init__(parent, bg=BG_DARK, **kwargs)
            tk.Label(self, text="Password Strength:", bg=BG_DARK, fg=TEXT_DIM,
                     font=FONT_LABEL).pack(anchor="w")
            self._track  = tk.Canvas(self, bg=BG_CARD, height=14,
                                      highlightthickness=0)
            self._track.pack(fill="x", pady=(2, 2))
            self._bar_id = self._track.create_rectangle(0, 0, 0, 14,
                                                         fill=ERROR, outline="")
            self._verdict = tk.Label(self, text="— enter a password —",
                                      bg=BG_DARK, fg=TEXT_DIM, font=FONT_MONO_SM)
            self._verdict.pack(anchor="w")

        def update(self, password: str) -> None:
            score  = self._score(password)
            width  = self._track.winfo_width()
            fill_w = int(width * score / 100)
            color, verdict = ERROR, "Weak"
            for lo, hi, col, lbl in self._LEVELS:
                if lo <= score < hi:
                    color, verdict = col, lbl
                    break
            self._track.coords(self._bar_id, 0, 0, fill_w, 14)
            self._track.itemconfig(self._bar_id, fill=color)
            entropy = self._entropy(password)
            self._verdict.config(
                text=f"{verdict}  —  ~{entropy:.1f} bits entropy", fg=color)

        @staticmethod
        def _entropy(pwd: str) -> float:
            if not pwd:
                return 0.0
            pool = 0
            if any(c.islower()     for c in pwd): pool += 26
            if any(c.isupper()     for c in pwd): pool += 26
            if any(c.isdigit()     for c in pwd): pool += 10
            if any(not c.isalnum() for c in pwd): pool += 32
            return math.log2(pool) * len(pwd) if pool > 0 else 0.0

        @staticmethod
        def _score(pwd: str) -> int:
            if not pwd:
                return 0
            score = min(len(pwd) * 4, 40)
            if any(c.islower()     for c in pwd): score += 10
            if any(c.isupper()     for c in pwd): score += 10
            if any(c.isdigit()     for c in pwd): score += 15
            if any(not c.isalnum() for c in pwd): score += 25
            return min(score, 100)


# ─────────────────────────────────────────────────────────────────────────────
# FRACTAL RENDERER
# ─────────────────────────────────────────────────────────────────────────────

if not _CLI_MODE:
    class FractalRenderer:
        """
        Off-thread fractal image renderer using PIL (Pillow).

        Produces Mandelbrot and Julia set images coloured using the design
        palette (black → indigo → cyan → magenta → white).
        """

        _COLOUR_STOPS = [
            (0,   (10,  10,  10)),
            (0.1, (26,  10,  74)),
            (0.4, (0,   180, 180)),
            (0.7, (0,   255, 255)),
            (0.9, (255, 0,   170)),
            (1.0, (255, 255, 255)),
        ]

        def __init__(self, engine: FractalKeyEngine) -> None:
            self.engine = engine

        @staticmethod
        def _lerp_colour(stops, t: float):
            t = max(0.0, min(1.0, t))
            for i in range(len(stops) - 1):
                t0, c0 = stops[i]
                t1, c1 = stops[i + 1]
                if t0 <= t <= t1:
                    frac = (t - t0) / (t1 - t0) if (t1 - t0) > 0 else 0
                    return tuple(int(c0[j] + (c1[j] - c0[j]) * frac) for j in range(3))
            return stops[-1][1]

        def render_mandelbrot(self, password: str, size: int = 300,
                              max_iter: int = 120):
            seed = self.engine._derive_seed(password)
            c    = self.engine._seed_to_complex(seed[0:8])
            img  = Image.new("RGB", (size, size))
            px   = img.load()
            x_min, x_max = -2.5, 1.0
            y_min, y_max = -1.25, 1.25
            for py in range(size):
                for pixx in range(size):
                    x0 = x_min + (x_max - x_min) * pixx / size
                    y0 = y_min + (y_max - y_min) * py / size
                    zr, zi = x0 + c.real * 0.15, y0 + c.imag * 0.15
                    n = 0
                    for n in range(max_iter):
                        if zr * zr + zi * zi > 4.0:
                            break
                        zr, zi = zr * zr - zi * zi + x0, 2 * zr * zi + y0
                    px[pixx, py] = self._lerp_colour(self._COLOUR_STOPS, n / max_iter)
            return img

        def render_julia(self, password: str, size: int = 300,
                         max_iter: int = 120):
            seed = self.engine._derive_seed(password)
            c    = self.engine._seed_to_complex(seed[8:16])
            img  = Image.new("RGB", (size, size))
            px   = img.load()
            for py in range(size):
                for pixx in range(size):
                    zr = (pixx / size) * 3.5 - 1.75
                    zi = (py  / size) * 3.5 - 1.75
                    n  = 0
                    for n in range(max_iter):
                        if zr * zr + zi * zi > 4.0:
                            break
                        zr, zi = zr * zr - zi * zi + c.real, 2 * zr * zi + c.imag
                    px[pixx, py] = self._lerp_colour(self._COLOUR_STOPS, n / max_iter)
            return img

        def render_fingerprint(self, password: str):
            W, H = 800, 400
            HALF = 400
            m_img = self.render_mandelbrot(password, size=HALF, max_iter=160)
            j_img = self.render_julia(password, size=HALF, max_iter=160)
            canvas = Image.new("RGB", (W, H), (13, 13, 26))
            canvas.paste(m_img, (0, 0))
            canvas.paste(j_img, (HALF, 0))
            draw = ImageDraw.Draw(canvas)
            try:
                fnt_title = ImageFont.truetype("consola.ttf", 18)
                fnt_sub   = ImageFont.truetype("consola.ttf", 13)
                fnt_small = ImageFont.truetype("consola.ttf", 11)
            except (IOError, AttributeError):
                fnt_title = ImageFont.load_default()
                fnt_sub   = fnt_title
                fnt_small = fnt_title
            _ = fnt_sub
            pwd_hash   = hashlib.sha256(password.encode("utf-8")).hexdigest()
            short_hash = pwd_hash[:32] + "..."
            timestamp  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            overlay = Image.new("RGBA", (W, 56), (13, 13, 26, 200))
            canvas  = canvas.convert("RGBA")
            canvas.paste(overlay, (0, 0), overlay)
            canvas  = canvas.convert("RGB")
            draw    = ImageDraw.Draw(canvas)
            draw.text((12, 6),  "FractalCrypt Key Fingerprint",
                      fill=(0, 255, 204), font=fnt_title)
            draw.text((12, 30), f"SHA-256: {short_hash}",
                      fill=(160, 160, 220), font=fnt_small)
            overlay2 = Image.new("RGBA", (W, 32), (13, 13, 26, 200))
            canvas   = canvas.convert("RGBA")
            canvas.paste(overlay2, (0, H - 32), overlay2)
            canvas   = canvas.convert("RGB")
            draw     = ImageDraw.Draw(canvas)
            draw.text((12, H - 26), f"Generated: {timestamp}",
                      fill=(102, 102, 170), font=fnt_small)
            draw.text((W - 150, H - 26), "DO NOT SHARE",
                      fill=(255, 0, 170), font=fnt_small)
            draw.line([(HALF, 0), (HALF, H)], fill=(42, 42, 90), width=2)
            for i in range(4):
                draw.rectangle([i, i, W - 1 - i, H - 1 - i],
                               outline=(0, 255, 204))
            draw.text((8, H - 56), "Mandelbrot Keystream Map",
                      fill=(0, 200, 160), font=fnt_small)
            draw.text((HALF + 8, H - 56), "Julia S-Box Map",
                      fill=(200, 0, 140), font=fnt_small)
            return canvas


# ─────────────────────────────────────────────────────────────────────────────
# TAB 1: ENCRYPT / DECRYPT
# ─────────────────────────────────────────────────────────────────────────────

if not _CLI_MODE:
    class EncryptTab(tk.Frame):
        """
        Tab 1: File selection, password entry, encrypt/decrypt controls, and log.

        Supports single-file, multi-file, and folder encryption modes.
        ASCII Armor mode wraps .fractal output in a PGP-style text envelope.
        Drag & drop is enabled when tkinterdnd2 is available.
        All cryptographic operations run in daemon threads.

        New in v4.0: optional "Shred original after encrypting" checkbox.
        """

        def __init__(self, parent, password_var, log,
                     shredder_tab_ref=None) -> None:
            super().__init__(parent, bg=BG_PANEL)
            self._password_var    = password_var
            self._log             = log
            self._files           = []
            self._busy            = False
            self._dnd_pulse_job   = None
            self._dnd_phase       = 0.0
            self._shredder_ref    = shredder_tab_ref  # set after Tab 5 is created

            self._build_ui()

        # ── UI construction ───────────────────────────────────────────────────

        def _build_ui(self) -> None:
            top = tk.Frame(self, bg=BG_PANEL)
            top.pack(fill="x", padx=12, pady=10)
            self._build_file_panel(top)
            self._build_controls_panel(top)

            sep = tk.Frame(self, bg=BORDER, height=1)
            sep.pack(fill="x", padx=12)

            log_frame = tk.Frame(self, bg=BG_PANEL)
            log_frame.pack(fill="both", expand=True, padx=12, pady=(0, 10))
            tk.Label(log_frame, text="  CONSOLE OUTPUT", bg=BG_PANEL, fg=TEXT_DIM,
                     font=FONT_MONO_SM, anchor="w").pack(fill="x")
            self._log.configure(bg=BG_DARK)

        def _build_file_panel(self, parent) -> None:
            frame = tk.Frame(parent, bg=BG_CARD, bd=0)
            frame.pack(side="left", fill="both", expand=True, padx=(0, 8))
            title_row = tk.Frame(frame, bg=BG_CARD)
            title_row.pack(fill="x", padx=8, pady=(8, 2))
            tk.Label(title_row, text="  SELECTED FILES", bg=BG_CARD, fg=ACCENT,
                     font=FONT_TITLE, anchor="w").pack(side="left")
            if DND_AVAILABLE:
                self._dnd_hint = tk.Label(title_row, text="  ⤵ Drop files here",
                                          bg=BG_CARD, fg=TEXT_DIM, font=FONT_MONO_SM)
                self._dnd_hint.pack(side="right", padx=4)
            else:
                tk.Label(title_row, text="  Install tkinterdnd2 for drag & drop",
                         bg=BG_CARD, fg=TEXT_DIM, font=FONT_MONO_SM).pack(side="right")

            self._drop_border = tk.Frame(frame, bg=BORDER, padx=1, pady=1)
            self._drop_border.pack(fill="both", expand=True, padx=8, pady=(0, 4))
            lb_frame = tk.Frame(self._drop_border, bg=BG_CARD)
            lb_frame.pack(fill="both", expand=True)
            scrollbar = tk.Scrollbar(lb_frame, bg=BG_DARK)
            scrollbar.pack(side="right", fill="y")
            self._listbox = tk.Listbox(
                lb_frame, bg="#0a0a18", fg=TEXT,
                selectbackground=BG_CARD, selectforeground=ACCENT,
                font=FONT_MONO_SM, relief="flat", bd=0,
                highlightthickness=0, yscrollcommand=scrollbar.set,
                activestyle="none",
            )
            self._listbox.pack(side="left", fill="both", expand=True)
            scrollbar.config(command=self._listbox.yview)

            if DND_AVAILABLE:
                self._listbox.drop_target_register(DND_FILES)
                self._listbox.dnd_bind("<<Drop>>",      self._on_dnd_drop)
                self._listbox.dnd_bind("<<DragEnter>>", self._on_dnd_enter)
                self._listbox.dnd_bind("<<DragLeave>>", self._on_dnd_leave)

            btn_row = tk.Frame(frame, bg=BG_CARD)
            btn_row.pack(fill="x", padx=8, pady=(2, 8))
            self._btn_add_files  = self._small_btn(btn_row, "+ Files",  self._add_files)
            self._btn_add_folder = self._small_btn(btn_row, "+ Folder", self._add_folder)
            self._btn_remove     = self._small_btn(btn_row, "✕ Remove", self._remove_selected)
            self._btn_clear      = self._small_btn(btn_row, "⌫ Clear",  self._clear_files)

            Tooltip(self._btn_add_files,  "Add one or more files to encrypt / decrypt.")
            Tooltip(self._btn_add_folder, "Add an entire folder (recursively zipped).")
            Tooltip(self._btn_remove,     "Remove the highlighted entry from the list.")
            Tooltip(self._btn_clear,      "Clear all selected files.")

        def _build_controls_panel(self, parent) -> None:
            frame = tk.Frame(parent, bg=BG_CARD, bd=0)
            frame.pack(side="right", fill="y", ipadx=8)

            tk.Label(frame, text="  PASSWORD", bg=BG_CARD, fg=ACCENT,
                     font=FONT_TITLE, anchor="w").pack(fill="x", padx=8, pady=(8, 2))
            pwd_row = tk.Frame(frame, bg=BG_CARD)
            pwd_row.pack(fill="x", padx=8, pady=(0, 6))
            self._pwd_entry = tk.Entry(
                pwd_row, textvariable=self._password_var, show="●",
                bg="#0a0a18", fg=TEXT, insertbackground=ACCENT,
                font=FONT_MONO, relief="flat", bd=4, width=24,
            )
            self._pwd_entry.pack(side="left", fill="x", expand=True)
            self._show_pwd = False
            self._eye_btn  = tk.Button(
                pwd_row, text="👁", bg=BG_CARD, fg=TEXT_DIM,
                font=("Consolas", 11), relief="flat", bd=0, cursor="hand2",
                command=self._toggle_pwd_show,
                activebackground=BG_CARD, activeforeground=ACCENT,
            )
            self._eye_btn.pack(side="left", padx=(4, 0))
            Tooltip(self._eye_btn, "Toggle password visibility.")

            tk.Label(frame, text="  OPTIONS", bg=BG_CARD, fg=ACCENT,
                     font=FONT_TITLE, anchor="w").pack(fill="x", padx=8, pady=(4, 2))
            self._armor_var  = tk.BooleanVar(value=False)
            self._folder_var = tk.BooleanVar(value=False)
            self._shred_var  = tk.BooleanVar(value=False)
            chk_armor = tk.Checkbutton(
                frame, text="  ASCII Armor  (.fractal.asc)",
                variable=self._armor_var, bg=BG_CARD, fg=TEXT,
                selectcolor=BG_DARK, activebackground=BG_CARD,
                activeforeground=ACCENT, font=FONT_LABEL, anchor="w",
            )
            chk_armor.pack(fill="x", padx=8, pady=1)
            chk_folder = tk.Checkbutton(
                frame, text="  Folder Mode  (zip then encrypt)",
                variable=self._folder_var, bg=BG_CARD, fg=TEXT,
                selectcolor=BG_DARK, activebackground=BG_CARD,
                activeforeground=ACCENT, font=FONT_LABEL, anchor="w",
            )
            chk_folder.pack(fill="x", padx=8, pady=1)
            chk_shred = tk.Checkbutton(
                frame, text="  Shred original after encrypting",
                variable=self._shred_var, bg=BG_CARD, fg=SHRED_RED,
                selectcolor=BG_DARK, activebackground=BG_CARD,
                activeforeground=SHRED_RED, font=FONT_LABEL, anchor="w",
            )
            chk_shred.pack(fill="x", padx=8, pady=1)
            Tooltip(chk_armor,
                    "Encode output as ASCII text (PGP-style). "
                    "Useful for sending encrypted data via e-mail.")
            Tooltip(chk_folder,
                    "Zip the entire folder before encrypting it "
                    "into a single .fractal file.")
            Tooltip(chk_shred,
                    "After successful encryption, securely shred the original "
                    "source file (3-pass DoD overwrite). A confirmation dialog will appear.")

            tk.Label(frame, text="  OUTPUT DIRECTORY", bg=BG_CARD, fg=ACCENT,
                     font=FONT_TITLE, anchor="w").pack(fill="x", padx=8, pady=(8, 2))
            out_row = tk.Frame(frame, bg=BG_CARD)
            out_row.pack(fill="x", padx=8, pady=(0, 6))
            self._out_var = tk.StringVar(value=os.path.expanduser("~"))
            self._out_entry = tk.Entry(
                out_row, textvariable=self._out_var,
                bg="#0a0a18", fg=TEXT_DIM, insertbackground=ACCENT,
                font=FONT_MONO_SM, relief="flat", bd=4, width=22,
            )
            self._out_entry.pack(side="left", fill="x", expand=True)
            browse_btn = tk.Button(
                out_row, text="…", bg=BG_CARD, fg=TEXT, font=FONT_LABEL,
                relief="flat", bd=0, cursor="hand2", command=self._browse_output,
                activebackground=BG_CARD, activeforeground=ACCENT,
            )
            browse_btn.pack(side="left", padx=(4, 0))
            Tooltip(browse_btn, "Choose the folder where output files will be saved.")

            self._progress = ttk.Progressbar(
                frame, orient="horizontal", mode="determinate", maximum=100,
            )
            self._progress.pack(fill="x", padx=8, pady=(4, 8))

            btn_frame = tk.Frame(frame, bg=BG_CARD)
            btn_frame.pack(fill="x", padx=8, pady=(0, 12))
            self._enc_btn = self._action_btn(
                btn_frame, "🔒  ENCRYPT", ACCENT, BG_DARK, self._on_encrypt,
            )
            self._enc_btn.pack(fill="x", pady=(0, 6))
            self._dec_btn = self._action_btn(
                btn_frame, "🔓  DECRYPT", ACCENT2, BG_DARK, self._on_decrypt,
            )
            self._dec_btn.pack(fill="x")
            Tooltip(self._enc_btn,
                    "Encrypt all selected files using PBKDF2 key stretching "
                    "(200,000 iterations). Each file gets its own random salt.")
            Tooltip(self._dec_btn,
                    "Decrypt selected .fractal or .fractal.asc files. "
                    "ASCII-armored files are detected automatically.")

        # ── Widget factories ──────────────────────────────────────────────────

        @staticmethod
        def _small_btn(parent, text, cmd):
            btn = tk.Button(
                parent, text=text, command=cmd,
                bg=BG_DARK, fg=TEXT_DIM, font=FONT_MONO_SM,
                relief="flat", bd=0, cursor="hand2", padx=6, pady=3,
                activebackground=BG_PANEL, activeforeground=ACCENT,
            )
            btn.pack(side="left", padx=2)
            return btn

        @staticmethod
        def _action_btn(parent, text, bg, fg, cmd):
            return tk.Button(
                parent, text=text, command=cmd,
                bg=bg, fg=fg, font=FONT_MONO_LG,
                relief="flat", bd=0, cursor="hand2", padx=12, pady=10,
                activebackground=BG_CARD, activeforeground=bg,
            )

        # ── Drag & drop ───────────────────────────────────────────────────────

        def _on_dnd_drop(self, event) -> None:
            self._stop_dnd_pulse()
            raw   = event.data.strip()
            paths = []
            if raw.startswith("{"):
                import re
                paths = re.findall(r"\{([^}]+)\}|(\S+)", raw)
                paths = [a or b for a, b in paths]
            else:
                paths = raw.split()

            added = 0
            for p in paths:
                p = p.strip().strip("{}")
                if p and os.path.exists(p) and p not in self._files:
                    self._files.append(p)
                    if os.path.isdir(p):
                        self._listbox.insert("end", f"📁 {os.path.basename(p)}/")
                    else:
                        self._listbox.insert("end", os.path.basename(p))
                    added += 1

            if added:
                self._log.accent(f"Dropped {added} item(s) onto file list.")

        def _on_dnd_enter(self, _event=None) -> None:
            self._dnd_phase = 0.0
            self._dnd_pulse()

        def _on_dnd_leave(self, _event=None) -> None:
            self._stop_dnd_pulse()

        def _dnd_pulse(self) -> None:
            phase  = (math.sin(self._dnd_phase) + 1) / 2
            r = int(0x2a + (0x00 - 0x2a) * phase)
            g = int(0x2a + (0xff - 0x2a) * phase)
            b = int(0x5a + (0xcc - 0x5a) * phase)
            colour = f"#{r:02x}{g:02x}{b:02x}"
            if hasattr(self, "_drop_border"):
                self._drop_border.config(bg=colour)
            self._dnd_phase += 0.2
            self._dnd_pulse_job = self.after(40, self._dnd_pulse)

        def _stop_dnd_pulse(self) -> None:
            if self._dnd_pulse_job:
                self.after_cancel(self._dnd_pulse_job)
                self._dnd_pulse_job = None
            if hasattr(self, "_drop_border"):
                self._drop_border.config(bg=BORDER)

        # ── Event handlers ────────────────────────────────────────────────────

        def _toggle_pwd_show(self) -> None:
            self._show_pwd = not self._show_pwd
            self._pwd_entry.config(show="" if self._show_pwd else "●")
            self._eye_btn.config(fg=ACCENT if self._show_pwd else TEXT_DIM)

        def _add_files(self) -> None:
            paths = filedialog.askopenfilenames(title="Select files to encrypt/decrypt")
            for p in paths:
                if p not in self._files:
                    self._files.append(p)
                    self._listbox.insert("end", os.path.basename(p))

        def _add_folder(self) -> None:
            path = filedialog.askdirectory(title="Select folder to encrypt")
            if path and path not in self._files:
                self._files.append(path)
                self._listbox.insert("end", f"📁 {os.path.basename(path)}/")

        def _remove_selected(self) -> None:
            sel = self._listbox.curselection()
            if sel:
                idx = sel[0]
                self._listbox.delete(idx)
                self._files.pop(idx)

        def _clear_files(self) -> None:
            self._listbox.delete(0, "end")
            self._files.clear()

        def _browse_output(self) -> None:
            path = filedialog.askdirectory(title="Select output directory")
            if path:
                self._out_var.set(path)

        def _set_busy(self, busy: bool) -> None:
            self._busy = busy
            state = "disabled" if busy else "normal"
            self._enc_btn.config(state=state)
            self._dec_btn.config(state=state)
            if not busy:
                self._progress["value"] = 0

        def _set_progress(self, fraction: float) -> None:
            self._progress["value"] = fraction * 100

        # ── Encrypt logic ─────────────────────────────────────────────────────

        def _on_encrypt(self) -> None:
            if not self._validate_inputs("encrypt"):
                return
            self._set_busy(True)
            threading.Thread(target=self._encrypt_worker, daemon=True).start()

        def _encrypt_worker(self) -> None:
            password     = self._password_var.get()
            out_dir      = self._out_var.get()
            use_armor    = self._armor_var.get()
            do_shred     = self._shred_var.get()
            cipher       = FractalCipherV2(verbose=False)
            errors       = 0
            shred_queue  = []  # files to shred after successful encryption

            self._log.accent("=" * 55)
            self._log.accent(f"Starting encryption of {len(self._files)} item(s)")

            for i, path in enumerate(self._files):
                try:
                    if os.path.isdir(path):
                        self._encrypt_folder(path, password, out_dir, use_armor, cipher)
                    else:
                        self._encrypt_single_file(path, password, out_dir,
                                                   use_armor, cipher, i)
                    if do_shred and os.path.isfile(path):
                        shred_queue.append(path)
                except Exception as exc:
                    self._log.error(f"  ✕  {os.path.basename(path)}: {exc}")
                    errors += 1

            if errors == 0:
                self._log.success("All files encrypted successfully ✓")
            else:
                self._log.warning(f"Finished with {errors} error(s).")

            # Trigger shred confirmation on main thread
            if shred_queue:
                self.after(0, lambda: self._prompt_shred_originals(shred_queue))
            else:
                self.after(0, lambda: self._set_busy(False))

        def _prompt_shred_originals(self, paths: list) -> None:
            """Show confirmation dialog then queue files for shredding."""
            self._set_busy(False)
            if self._shredder_ref is not None:
                # Delegate to ShredderTab's confirmation dialog
                self._shredder_ref.queue_shred_with_confirm(paths)
            else:
                # Fallback: simple messagebox
                names = "\n".join(f"  • {os.path.basename(p)}" for p in paths)
                if messagebox.askyesno(
                    "Shred originals?",
                    f"Shred the following original files?\n{names}\n\n"
                    "3-pass DoD overwrite. No recovery possible.",
                ):
                    threading.Thread(
                        target=self._shred_worker, args=(paths,), daemon=True
                    ).start()

        def _shred_worker(self, paths: list) -> None:
            for p in paths:
                try:
                    shred_file(p, passes=3, log_cb=lambda m: self.after(
                        0, lambda m=m: self._log.warning(m)))
                except Exception as exc:
                    self.after(0, lambda exc=exc: self._log.error(str(exc)))

        def _encrypt_single_file(self, path, password, out_dir,
                                  use_armor, cipher, idx) -> None:
            basename    = os.path.basename(path)
            out_name    = basename + (".fractal.asc" if use_armor else ".fractal")
            out_path    = os.path.join(out_dir, out_name)
            self._log.info(f"  Encrypting: {basename}")

            def progress(f):
                self.after(0, lambda: self._set_progress(f))

            tmp_fractal = out_path if not use_armor else tempfile.mktemp(suffix=".fractal")
            salt = cipher.encrypt_v2(path, tmp_fractal, password, progress_cb=progress)

            if use_armor:
                with open(tmp_fractal, "rb") as fh:
                    blob = fh.read()
                text = armor_encode(blob, salt)
                with open(out_path, "w", encoding="utf-8") as fh:
                    fh.write(text)
                os.remove(tmp_fractal)

            self._log.success(f"  ✓  {out_name}")

        def _encrypt_folder(self, folder_path, password, out_dir,
                             use_armor, cipher) -> None:
            folder_name = os.path.basename(folder_path.rstrip("/\\"))
            self._log.info(f"  Zipping folder: {folder_name}/")
            zip_buf = io.BytesIO()
            with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, _dirs, files in os.walk(folder_path):
                    for fname in files:
                        fpath   = os.path.join(root, fname)
                        arcname = os.path.relpath(fpath, os.path.dirname(folder_path))
                        zf.write(fpath, arcname)
            zip_bytes    = zip_buf.getvalue()
            archive_name = folder_name + ".zip"
            blob         = cipher.encrypt_v2_bytes(zip_bytes, archive_name, password)
            salt         = blob[8:24]
            ext          = ".fractal.asc" if use_armor else ".fractal"
            out_path     = os.path.join(out_dir, folder_name + ext)
            if use_armor:
                with open(out_path, "w", encoding="utf-8") as fh:
                    fh.write(armor_encode(blob, salt))
            else:
                with open(out_path, "wb") as fh:
                    fh.write(blob)
            self._log.success(f"  ✓  {folder_name + ext}")

        # ── Decrypt logic ─────────────────────────────────────────────────────

        def _on_decrypt(self) -> None:
            if not self._validate_inputs("decrypt"):
                return
            self._set_busy(True)
            threading.Thread(target=self._decrypt_worker, daemon=True).start()

        def _decrypt_worker(self) -> None:
            password = self._password_var.get()
            out_dir  = self._out_var.get()
            cipher   = FractalCipherV2(verbose=False)
            errors   = 0
            self._log.accent("=" * 55)
            self._log.accent(f"Starting decryption of {len(self._files)} item(s)")
            for path in self._files:
                try:
                    self._decrypt_single(path, password, out_dir, cipher)
                except Exception as exc:
                    self._log.error(f"  ✕  {os.path.basename(path)}: {exc}")
                    errors += 1
            if errors == 0:
                self._log.success("All files decrypted successfully ✓")
            else:
                self._log.warning(f"Finished with {errors} error(s).")
            self.after(0, lambda: self._set_busy(False))

        def _decrypt_single(self, path, password, out_dir, cipher) -> None:
            basename = os.path.basename(path)
            self._log.info(f"  Decrypting: {basename}")

            def progress(f):
                self.after(0, lambda: self._set_progress(f))

            if is_armored(path):
                self._log.info("  Detected ASCII armor — decoding…")
                with open(path, "r", encoding="utf-8") as fh:
                    text = fh.read()
                blob = armor_decode(text)
                with tempfile.NamedTemporaryFile(suffix=".fractal", delete=False) as tf:
                    tmp_path = tf.name
                    tf.write(blob)
                try:
                    tmp_out  = os.path.join(out_dir, "_tmp_dec_")
                    orig     = cipher.decrypt_v2(tmp_path, tmp_out, password, progress)
                    out_path = os.path.join(out_dir, orig)
                    if os.path.exists(tmp_out):
                        self._handle_output(tmp_out, out_path, out_dir)
                finally:
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass
            else:
                with tempfile.NamedTemporaryFile(suffix="_dec", delete=False) as tf:
                    tmp_out = tf.name
                try:
                    orig     = cipher.decrypt_v2(path, tmp_out, password, progress)
                    out_path = os.path.join(out_dir, orig)
                    self._handle_output(tmp_out, out_path, out_dir)
                finally:
                    try:
                        if os.path.exists(tmp_out):
                            os.remove(tmp_out)
                    except OSError:
                        pass

            self._log.success("  ✓  Decrypted successfully")

        def _handle_output(self, tmp_path: str, out_path: str, out_dir: str) -> None:
            # Read the decoded file once; reuse bytes for both ZIP detection and extraction
            with open(tmp_path, "rb") as fh:
                full_data = fh.read()
            is_zip = full_data[:4] == b"PK\x03\x04"
            if is_zip and out_path.endswith(".zip"):
                extract_dir = os.path.join(out_dir, os.path.splitext(
                    os.path.basename(out_path))[0])
                os.makedirs(extract_dir, exist_ok=True)
                with zipfile.ZipFile(io.BytesIO(full_data)) as zf:
                    zf.extractall(extract_dir)
                self._log.success(f"  [OK]  Extracted to: {extract_dir}")
            else:
                os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
                shutil.move(tmp_path, out_path)

        # ── Validation ────────────────────────────────────────────────────────

        def _validate_inputs(self, op: str) -> bool:
            if not self._files:
                messagebox.showwarning("No files",
                                       "Please add at least one file or folder.")
                return False
            if not self._password_var.get():
                messagebox.showwarning("No password", "Please enter a password.")
                return False
            out_dir = self._out_var.get()
            if not os.path.isdir(out_dir):
                try:
                    os.makedirs(out_dir, exist_ok=True)
                except OSError as exc:
                    messagebox.showerror("Output error",
                                         f"Cannot create output directory:\n{exc}")
                    return False
            return True


# ─────────────────────────────────────────────────────────────────────────────
# TAB 2: KEY VISUALIZER
# ─────────────────────────────────────────────────────────────────────────────

if not _CLI_MODE:
    class VisualizerTab(tk.Frame):
        """Tab 2: Fractal Key Visualizer."""

        def __init__(self, parent, password_var, log) -> None:
            super().__init__(parent, bg=BG_PANEL)
            self._password_var = password_var
            self._log          = log
            self._engine       = FractalKeyEngine()
            self._renderer     = None if not PIL_AVAILABLE else FractalRenderer(self._engine)
            self._rendering    = False
            self._pulse_job    = None
            self._last_m_img   = None
            self._last_j_img   = None
            self._last_password = ""
            self._build_ui()

        def _build_ui(self) -> None:
            hdr = tk.Frame(self, bg=BG_PANEL)
            hdr.pack(fill="x", padx=14, pady=(10, 4))
            tk.Label(hdr, text="🔮  KEY VISUALIZER", bg=BG_PANEL, fg=ACCENT,
                     font=FONT_MONO_XL).pack(side="left")
            tk.Label(hdr, text="Password → fractal parameter → unique visual fingerprint",
                     bg=BG_PANEL, fg=TEXT_DIM, font=FONT_MONO_SM).pack(
                         side="left", padx=14)

            pwd_row = tk.Frame(self, bg=BG_PANEL)
            pwd_row.pack(fill="x", padx=14, pady=4)
            tk.Label(pwd_row, text="Password:", bg=BG_PANEL, fg=TEXT,
                     font=FONT_LABEL).pack(side="left")
            self._pwd_entry = tk.Entry(
                pwd_row, textvariable=self._password_var,
                show="●", bg="#0a0a18", fg=TEXT,
                insertbackground=ACCENT, font=FONT_MONO,
                relief="flat", bd=4, width=30,
            )
            self._pwd_entry.pack(side="left", padx=8)
            self._vis_btn = tk.Button(
                pwd_row, text="▶  VISUALIZE KEY",
                bg=ACCENT, fg=BG_DARK, font=FONT_MONO_LG,
                relief="flat", bd=0, cursor="hand2", padx=12, pady=6,
                command=self._on_visualize,
                activebackground=BG_CARD, activeforeground=ACCENT,
            )
            self._vis_btn.pack(side="left", padx=8)
            Tooltip(self._vis_btn,
                    "Render Mandelbrot and Julia fractals seeded by the password.")

            self._export_btn = tk.Button(
                pwd_row, text="💾  EXPORT PNG",
                bg=BG_CARD, fg=TEXT_DIM, font=FONT_MONO_LG,
                relief="flat", bd=0, cursor="hand2", padx=12, pady=6,
                command=self._on_export,
                activebackground=BG_PANEL, activeforeground=ACCENT,
                state="disabled",
            )
            self._export_btn.pack(side="left", padx=4)
            Tooltip(self._export_btn,
                    "Export an 800×400 key-fingerprint PNG. Requires Pillow.")

            self._status_lbl = tk.Label(pwd_row, text="", bg=BG_PANEL,
                                         fg=WARNING, font=FONT_MONO_SM)
            self._status_lbl.pack(side="left", padx=8)

            canvas_row = tk.Frame(self, bg=BG_PANEL)
            canvas_row.pack(pady=10)

            if not PIL_AVAILABLE:
                tk.Label(canvas_row,
                         text="⚠  Pillow (PIL) is not installed.\n"
                              "Install it with:  pip install Pillow\n"
                              "The Key Visualizer requires Pillow to render fractal images.",
                         bg=BG_CARD, fg=WARNING, font=FONT_MONO, padx=20, pady=20,
                         ).pack(fill="both", expand=True)
                return

            m_frame = tk.Frame(canvas_row, bg=BG_PANEL)
            m_frame.pack(side="left", padx=12)
            tk.Label(m_frame, text="Mandelbrot Keystream Map",
                     bg=BG_PANEL, fg=ACCENT, font=FONT_TITLE).pack()
            self._m_border = tk.Frame(m_frame, bg=BORDER, padx=2, pady=2)
            self._m_border.pack()
            self._m_canvas = tk.Canvas(self._m_border, width=300, height=300,
                                        bg="#0a0a0a", highlightthickness=0)
            self._m_canvas.pack()

            j_frame = tk.Frame(canvas_row, bg=BG_PANEL)
            j_frame.pack(side="left", padx=12)
            tk.Label(j_frame, text="Julia S-Box Map",
                     bg=BG_PANEL, fg=ACCENT2, font=FONT_TITLE).pack()
            self._j_border = tk.Frame(j_frame, bg=BORDER, padx=2, pady=2)
            self._j_border.pack()
            self._j_canvas = tk.Canvas(self._j_border, width=300, height=300,
                                        bg="#0a0a0a", highlightthickness=0)
            self._j_canvas.pack()

            self._m_img = None
            self._j_img = None

            self._meter = PasswordMeter(self)
            self._meter.pack(fill="x", padx=20, pady=(6, 0))
            self._password_var.trace_add("write", self._on_password_change)

        def _on_password_change(self, *_args) -> None:
            if hasattr(self, "_meter"):
                self._meter.update(self._password_var.get())

        def _on_visualize(self) -> None:
            if not PIL_AVAILABLE or self._rendering:
                return
            password = self._password_var.get()
            if not password:
                messagebox.showwarning("No password", "Enter a password to visualize.")
                return
            self._rendering     = True
            self._last_password = password
            self._vis_btn.config(state="disabled")
            self._export_btn.config(state="disabled")
            self._status_lbl.config(text="Rendering…", fg=WARNING)
            self._start_pulse()
            threading.Thread(
                target=self._render_worker, args=(password,), daemon=True
            ).start()

        def _render_worker(self, password: str) -> None:
            try:
                m_img = self._renderer.render_mandelbrot(password)
                j_img = self._renderer.render_julia(password)
                self._last_m_img = m_img
                self._last_j_img = j_img
                self.after(0, lambda: self._show_images(m_img, j_img))
            except Exception as exc:
                self.after(0, lambda: self._status_lbl.config(
                    text=f"Error: {exc}", fg=ERROR))
            finally:
                self.after(0, self._stop_render)

        def _show_images(self, m_img, j_img) -> None:
            self._m_img = ImageTk.PhotoImage(m_img)
            self._j_img = ImageTk.PhotoImage(j_img)
            self._m_canvas.create_image(0, 0, anchor="nw", image=self._m_img)
            self._j_canvas.create_image(0, 0, anchor="nw", image=self._j_img)

        def _stop_render(self) -> None:
            self._rendering = False
            self._vis_btn.config(state="normal")
            self._export_btn.config(state="normal" if PIL_AVAILABLE else "disabled")
            self._status_lbl.config(text="Done  ✓", fg=SUCCESS)
            self._stop_pulse()

        def _on_export(self) -> None:
            if not PIL_AVAILABLE:
                messagebox.showerror("Pillow required",
                                     "Pillow is required for PNG export.\n"
                                     "Install with: pip install Pillow")
                return
            password = self._last_password or self._password_var.get()
            if not password:
                messagebox.showwarning("No password", "Visualize a key first.")
                return
            pwd_hash     = hashlib.sha256(password.encode()).hexdigest()
            default_name = f"fractal_key_{pwd_hash[:8]}.png"
            out_path = filedialog.asksaveasfilename(
                title="Save Key Fingerprint PNG",
                defaultextension=".png",
                filetypes=[("PNG Image", "*.png")],
                initialfile=default_name,
            )
            if not out_path:
                return
            self._export_btn.config(state="disabled")
            self._status_lbl.config(text="Generating fingerprint…", fg=WARNING)
            threading.Thread(
                target=self._export_worker, args=(password, out_path), daemon=True
            ).start()

        def _export_worker(self, password: str, out_path: str) -> None:
            try:
                fingerprint = self._renderer.render_fingerprint(password)
                fingerprint.save(out_path, "PNG")
                self.after(0, lambda: self._status_lbl.config(
                    text="Exported ✓", fg=SUCCESS))
                self.after(0, lambda: self._log.success(
                    f"Key fingerprint saved → {out_path}"))
            except Exception as exc:
                self.after(0, lambda: self._status_lbl.config(
                    text=f"Export error: {exc}", fg=ERROR))
            finally:
                self.after(0, lambda: self._export_btn.config(state="normal"))

        def _start_pulse(self) -> None:
            if not PIL_AVAILABLE:
                return
            self._pulse_phase = 0
            self._pulse()

        def _pulse(self) -> None:
            if not self._rendering:
                return
            phase  = (math.sin(self._pulse_phase) + 1) / 2
            r = int(0x00 + (0xff - 0x00) * phase)
            g = int(0xff + (0x00 - 0xff) * phase)
            b = int(0xcc + (0xaa - 0xcc) * phase)
            colour = f"#{r:02x}{g:02x}{b:02x}"
            if hasattr(self, "_m_border"):
                self._m_border.config(bg=colour)
                self._j_border.config(bg=colour)
            self._pulse_phase += 0.15
            self._pulse_job = self.after(50, self._pulse)

        def _stop_pulse(self) -> None:
            if self._pulse_job:
                self.after_cancel(self._pulse_job)
                self._pulse_job = None
            if PIL_AVAILABLE and hasattr(self, "_m_border"):
                self._m_border.config(bg=ACCENT)
                self._j_border.config(bg=ACCENT2)


# ─────────────────────────────────────────────────────────────────────────────
# TAB 3: KEYSTREAM ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

if not _CLI_MODE:
    class AnalysisTab(tk.Frame):
        """Tab 3: Keystream Randomness Histogram."""

        KEYSTREAM_LEN = 1024
        NUM_BINS      = 16

        def __init__(self, parent, password_var) -> None:
            super().__init__(parent, bg=BG_PANEL)
            self._password_var = password_var
            self._engine       = FractalKeyEngine()
            self._analyzing    = False
            self._build_ui()

        def _build_ui(self) -> None:
            hdr = tk.Frame(self, bg=BG_PANEL)
            hdr.pack(fill="x", padx=14, pady=(10, 4))
            tk.Label(hdr, text="📊  KEYSTREAM ANALYSIS", bg=BG_PANEL, fg=ACCENT,
                     font=FONT_MONO_XL).pack(side="left")
            tk.Label(hdr, text="Statistical randomness quality of the fractal keystream",
                     bg=BG_PANEL, fg=TEXT_DIM, font=FONT_MONO_SM).pack(
                         side="left", padx=14)

            pwd_row = tk.Frame(self, bg=BG_PANEL)
            pwd_row.pack(fill="x", padx=14, pady=4)
            tk.Label(pwd_row, text="Password:", bg=BG_PANEL, fg=TEXT,
                     font=FONT_LABEL).pack(side="left")
            self._pwd_entry = tk.Entry(
                pwd_row, textvariable=self._password_var,
                show="●", bg="#0a0a18", fg=TEXT,
                insertbackground=ACCENT, font=FONT_MONO,
                relief="flat", bd=4, width=30,
            )
            self._pwd_entry.pack(side="left", padx=8)
            self._analyze_btn = tk.Button(
                pwd_row, text="▶  ANALYZE",
                bg=ACCENT2, fg=BG_DARK, font=FONT_MONO_LG,
                relief="flat", bd=0, cursor="hand2", padx=12, pady=6,
                command=self._on_analyze,
                activebackground=BG_CARD, activeforeground=ACCENT2,
            )
            self._analyze_btn.pack(side="left", padx=8)
            Tooltip(self._analyze_btn,
                    "Generate 1024 bytes of fractal keystream and plot byte distribution.")
            self._status_lbl = tk.Label(pwd_row, text="", bg=BG_PANEL,
                                         fg=WARNING, font=FONT_MONO_SM)
            self._status_lbl.pack(side="left", padx=8)

            canvas_frame = tk.Frame(self, bg=BG_CARD, padx=12, pady=10)
            canvas_frame.pack(fill="x", padx=14, pady=6)
            tk.Label(canvas_frame, text="Byte Value Distribution  (16 bins, 0–255 range)",
                     bg=BG_CARD, fg=TEXT_DIM, font=FONT_MONO_SM, anchor="w").pack(fill="x")
            self._histogram = tk.Canvas(
                canvas_frame, width=600, height=200,
                bg="#080810", highlightthickness=1,
                highlightbackground=BORDER,
            )
            self._histogram.pack(pady=(4, 0))

            stats = tk.Frame(self, bg=BG_CARD, padx=12, pady=8)
            stats.pack(fill="x", padx=14, pady=(0, 8))
            self._chi_lbl     = self._stat_row(stats, "Chi-squared:", "—")
            self._entropy_lbl = self._stat_row(stats, "Shannon Entropy:", "—")
            self._verdict_lbl = self._stat_row(stats, "Verdict:", "—", fg=TEXT)
            self._draw_empty_histogram()

        @staticmethod
        def _stat_row(parent, label, value, fg=TEXT_DIM):
            row = tk.Frame(parent, bg=BG_CARD)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=f"  {label}", bg=BG_CARD, fg=TEXT_DIM,
                     font=FONT_LABEL, width=22, anchor="w").pack(side="left")
            val_lbl = tk.Label(row, text=value, bg=BG_CARD, fg=fg,
                               font=FONT_MONO_LG, anchor="w")
            val_lbl.pack(side="left")
            return val_lbl

        def _draw_empty_histogram(self) -> None:
            c = self._histogram
            W, H, M = 600, 200, 30
            c.delete("all")
            c.create_line(M, 5, M, H - M, fill=BORDER, width=1)
            c.create_line(M, H - M, W - 5, H - M, fill=BORDER, width=1)
            for lv in [0, 64, 128, 192, 255]:
                x = M + (lv / 256) * (W - M - 5)
                c.create_text(x, H - 14, text=str(lv),
                              fill=TEXT_DIM, font=FONT_MONO_SM)

        def _draw_histogram(self, counts: list) -> None:
            c = self._histogram
            W, H, M = 600, 200, 30
            usable_w = W - M - 10
            usable_h = H - M - 10
            bar_w    = usable_w / self.NUM_BINS
            max_cnt  = max(counts) if max(counts) > 0 else 1
            c.delete("all")
            ideal_count = self.KEYSTREAM_LEN / self.NUM_BINS
            ideal_y     = H - M - (ideal_count / max_cnt) * usable_h
            c.create_line(M, ideal_y, W - 5, ideal_y, fill=ERROR, dash=(6, 4), width=1)
            c.create_text(W - 8, ideal_y - 8, text="ideal",
                          fill=ERROR, font=FONT_MONO_SM, anchor="e")
            colours = [ACCENT, "#00ddaa", "#00bbff", "#4488ff",
                       ACCENT2, "#ff44cc", "#ff6688", "#ff8844"] * 2
            for i, cnt in enumerate(counts):
                x0    = M + i * bar_w + 2
                x1    = x0 + bar_w - 4
                bar_h = (cnt / max_cnt) * usable_h
                y0    = H - M - bar_h
                y1    = H - M
                c.create_rectangle(x0, y0, x1, y1, fill=colours[i % len(colours)],
                                   outline="")
                c.create_text((x0 + x1) / 2, y0 - 4, text=str(cnt),
                              fill=TEXT_DIM, font=FONT_MONO_SM)
            c.create_line(M, 5, M, H - M, fill=BORDER)
            c.create_line(M, H - M, W - 5, H - M, fill=BORDER)
            for lv in [0, 64, 128, 192, 255]:
                x = M + (lv / 256) * usable_w
                c.create_text(x, H - 14, text=str(lv),
                              fill=TEXT_DIM, font=FONT_MONO_SM)
            for pct in [0, 50, 100]:
                y = H - M - (pct / 100) * usable_h
                c.create_text(M - 4, y, text=str(int(max_cnt * pct / 100)),
                              fill=TEXT_DIM, font=FONT_MONO_SM, anchor="e")

        @staticmethod
        def _chi_squared(observed: list, expected: float) -> float:
            return sum((o - expected) ** 2 / expected for o in observed)

        @staticmethod
        def _shannon_entropy(data: bytes) -> float:
            if not data:
                return 0.0
            freq = [0] * 256
            for b in data:
                freq[b] += 1
            n = len(data)
            return -sum((f / n) * math.log2(f / n) for f in freq if f > 0)

        def _on_analyze(self) -> None:
            if self._analyzing:
                return
            password = self._password_var.get()
            if not password:
                messagebox.showwarning("No password", "Enter a password to analyze.")
                return
            self._analyzing = True
            self._analyze_btn.config(state="disabled")
            self._status_lbl.config(text="Analyzing…", fg=WARNING)
            threading.Thread(
                target=self._analyze_worker, args=(password,), daemon=True
            ).start()

        def _analyze_worker(self, password: str) -> None:
            try:
                dummy_salt    = bytes(16)
                stretched_key = stretch_password(password, dummy_salt)
                keystream     = self._engine.mandelbrot_keystream(
                    stretched_key, self.KEYSTREAM_LEN)
                bin_size = 256 // self.NUM_BINS
                counts   = [0] * self.NUM_BINS
                for b in keystream:
                    counts[b // bin_size] += 1
                expected = self.KEYSTREAM_LEN / self.NUM_BINS
                chi2     = self._chi_squared(counts, expected)
                entropy  = self._shannon_entropy(keystream)
                if chi2 < 20 and entropy > 7.8:
                    verdict, vcol = "Excellent randomness ✓", SUCCESS
                elif chi2 < 40 and entropy > 7.5:
                    verdict, vcol = "Good randomness ✓", WARNING
                else:
                    verdict, vcol = "Weak randomness ✗", ERROR
                self.after(0, lambda: self._show_results(counts, chi2, entropy, verdict, vcol))
            except Exception as exc:
                self.after(0, lambda: self._status_lbl.config(
                    text=f"Error: {exc}", fg=ERROR))
            finally:
                self.after(0, self._stop_analysis)

        def _show_results(self, counts, chi2, entropy, verdict, vcol) -> None:
            self._draw_histogram(counts)
            self._chi_lbl.config(
                text=f"{chi2:.2f}  (lower is better, ideal ≈ 15)",
                fg=SUCCESS if chi2 < 30 else WARNING)
            self._entropy_lbl.config(
                text=f"{entropy:.4f} bits/byte  (max = 8.0)",
                fg=SUCCESS if entropy > 7.8 else WARNING)
            self._verdict_lbl.config(text=verdict, fg=vcol)

        def _stop_analysis(self) -> None:
            self._analyzing = False
            self._analyze_btn.config(state="normal")
            self._status_lbl.config(text="Done  ✓", fg=SUCCESS)


# ─────────────────────────────────────────────────────────────────────────────
# TAB 4: SECURE NOTES
# ─────────────────────────────────────────────────────────────────────────────

if not _CLI_MODE:
    class SecureNotesTab(tk.Frame):
        """Tab 4: Encrypted text note editor."""

        _NOTE_EXT    = ".fractal.note"
        _PLACEHOLDER = "Type your secret note here…"

        def __init__(self, parent, password_var) -> None:
            super().__init__(parent, bg=BG_PANEL)
            self._password_var       = password_var
            self._cipher             = FractalCipherV2(verbose=False)
            self._busy               = False
            self._placeholder_active = False
            self._build_ui()

        def _build_ui(self) -> None:
            hdr = tk.Frame(self, bg=BG_PANEL)
            hdr.pack(fill="x", padx=14, pady=(10, 4))
            tk.Label(hdr, text="📝  SECURE NOTES", bg=BG_PANEL, fg=ACCENT,
                     font=FONT_MONO_XL).pack(side="left")
            tk.Label(hdr, text="Encrypt/decrypt text notes in-memory with PBKDF2",
                     bg=BG_PANEL, fg=TEXT_DIM, font=FONT_MONO_SM).pack(
                         side="left", padx=12)

            pwd_row = tk.Frame(self, bg=BG_PANEL)
            pwd_row.pack(fill="x", padx=14, pady=(0, 4))
            tk.Label(pwd_row, text="Password:", bg=BG_PANEL, fg=TEXT,
                     font=FONT_LABEL).pack(side="left")
            self._pwd_entry = tk.Entry(
                pwd_row, textvariable=self._password_var,
                show="●", bg="#0a0a18", fg=TEXT,
                insertbackground=ACCENT, font=FONT_MONO,
                relief="flat", bd=4, width=32,
            )
            self._pwd_entry.pack(side="left", padx=8)
            self._show_pwd = False
            self._eye_btn  = tk.Button(
                pwd_row, text="👁", bg=BG_PANEL, fg=TEXT_DIM,
                font=("Consolas", 11), relief="flat", bd=0, cursor="hand2",
                command=self._toggle_pwd,
                activebackground=BG_PANEL, activeforeground=ACCENT,
            )
            self._eye_btn.pack(side="left")
            Tooltip(self._eye_btn, "Toggle password visibility.")

            editor_frame = tk.Frame(self, bg=BG_DARK)
            editor_frame.pack(fill="both", expand=True, padx=14, pady=(2, 0))
            self._gutter = tk.Canvas(editor_frame, width=36, bg="#080810",
                                      highlightthickness=0)
            self._gutter.pack(side="left", fill="y")
            txt_frame = tk.Frame(editor_frame, bg=BG_DARK)
            txt_frame.pack(side="left", fill="both", expand=True)
            txt_scroll = tk.Scrollbar(txt_frame, orient="vertical", bg=BG_CARD)
            txt_scroll.pack(side="right", fill="y")
            self._editor = tk.Text(
                txt_frame, bg=BG_DARK, fg=TEXT, insertbackground=ACCENT,
                font=FONT_NOTE, relief="flat", bd=0, wrap="word", undo=True,
                selectbackground=BG_CARD, yscrollcommand=txt_scroll.set,
                padx=8, pady=6,
            )
            self._editor.pack(fill="both", expand=True)
            txt_scroll.config(command=self._editor.yview)
            self._editor.tag_configure("hash_line",  foreground=NOTE_HASH)
            self._editor.tag_configure("quote_line", foreground=ACCENT)
            self._show_placeholder()
            self._editor.bind("<KeyRelease>", self._on_key_release)
            self._editor.bind("<FocusIn>",    self._on_focus_in)
            self._editor.bind("<FocusOut>",   self._on_focus_out)

            bot = tk.Frame(self, bg=BG_PANEL)
            bot.pack(fill="x", padx=14, pady=4)
            self._enc_note_btn = self._note_btn(
                bot, "🔒 ENCRYPT NOTE", ACCENT, BG_DARK, self._on_encrypt_note)
            self._dec_note_btn = self._note_btn(
                bot, "🔓 DECRYPT NOTE", ACCENT2, BG_DARK, self._on_decrypt_note)
            self._copy_btn = self._note_btn(
                bot, "📋 COPY ENCRYPTED", BG_CARD, ACCENT, self._on_copy_encrypted)
            self._clear_btn = self._note_btn(
                bot, "🗑 CLEAR", BG_CARD, ERROR, self._on_clear)
            Tooltip(self._enc_note_btn, "Encrypt the note text and save as a .fractal.note file.")
            Tooltip(self._dec_note_btn, "Open a .fractal.note file and decrypt it into the editor.")
            Tooltip(self._copy_btn, "Encrypt in-memory and copy ASCII-armored ciphertext to clipboard.")
            Tooltip(self._clear_btn, "Clear the note editor (with confirmation).")
            self._counter_lbl = tk.Label(
                bot, text="0 chars", bg=BG_PANEL, fg=TEXT_DIM, font=FONT_MONO_SM)
            self._counter_lbl.pack(side="right", padx=8)

        @staticmethod
        def _note_btn(parent, text, bg, fg, cmd):
            btn = tk.Button(
                parent, text=text, command=cmd,
                bg=bg, fg=fg, font=FONT_MONO_SM,
                relief="flat", bd=0, cursor="hand2",
                padx=10, pady=6,
                activebackground=BG_CARD, activeforeground=fg,
            )
            btn.pack(side="left", padx=4)
            return btn

        def _show_placeholder(self) -> None:
            self._editor.config(fg=TEXT_DIM)
            self._editor.insert("1.0", self._PLACEHOLDER)
            self._placeholder_active = True

        def _clear_placeholder(self) -> None:
            if self._placeholder_active:
                self._editor.delete("1.0", "end")
                self._editor.config(fg=TEXT)
                self._placeholder_active = False

        def _on_focus_in(self, _event=None) -> None:
            self._clear_placeholder()

        def _on_focus_out(self, _event=None) -> None:
            if not self._editor.get("1.0", "end-1c").strip():
                self._show_placeholder()

        def _on_key_release(self, _event=None) -> None:
            self._update_gutter()
            self._update_counter()
            self._apply_syntax()

        def _update_gutter(self) -> None:
            self._gutter.delete("all")
            i    = self._editor.index("@0,0")
            line = int(i.split(".")[0])
            while True:
                dline = self._editor.dlineinfo(f"{line}.0")
                if dline is None:
                    break
                self._gutter.create_text(
                    32, dline[1] + 6, text=str(line), anchor="e",
                    fill=TEXT_DIM, font=FONT_MONO_SM)
                line += 1
                if line > int(self._editor.index("end").split(".")[0]) + 1:
                    break

        def _update_counter(self) -> None:
            text = self._get_note_text()
            nc   = len(text)
            nb   = len(text.encode("utf-8"))
            enc_est = nb + 80
            self._counter_lbl.config(text=f"{nc} chars | ~{enc_est} bytes encrypted")

        def _apply_syntax(self) -> None:
            if self._placeholder_active:
                return
            self._editor.tag_remove("hash_line",  "1.0", "end")
            self._editor.tag_remove("quote_line", "1.0", "end")
            line_count = int(self._editor.index("end").split(".")[0])
            for i in range(1, line_count + 1):
                line_start = f"{i}.0"
                line_end   = f"{i}.end"
                first_char = self._editor.get(line_start, f"{i}.1")
                if first_char == "#":
                    self._editor.tag_add("hash_line",  line_start, line_end)
                elif first_char == ">":
                    self._editor.tag_add("quote_line", line_start, line_end)

        def _get_note_text(self) -> str:
            if self._placeholder_active:
                return ""
            return self._editor.get("1.0", "end-1c")

        def _toggle_pwd(self) -> None:
            self._show_pwd = not self._show_pwd
            self._pwd_entry.config(show="" if self._show_pwd else "●")
            self._eye_btn.config(fg=ACCENT if self._show_pwd else TEXT_DIM)

        def _on_encrypt_note(self) -> None:
            text = self._get_note_text()
            if not text.strip():
                messagebox.showwarning("Empty note", "The note is empty. Nothing to encrypt.")
                return
            password = self._password_var.get()
            if not password:
                messagebox.showwarning("No password", "Enter a password.")
                return
            out_path = filedialog.asksaveasfilename(
                title="Save encrypted note",
                defaultextension=self._NOTE_EXT,
                filetypes=[("Fractal Note", f"*{self._NOTE_EXT}"), ("All files", "*.*")],
                initialfile="note" + self._NOTE_EXT,
            )
            if not out_path:
                return
            self._set_busy(True)
            threading.Thread(
                target=self._encrypt_note_worker,
                args=(text, password, out_path), daemon=True
            ).start()

        def _encrypt_note_worker(self, text: str, password: str, out_path: str) -> None:
            try:
                plaintext = text.encode("utf-8")
                blob      = self._cipher.encrypt_v2_bytes(plaintext, "note.txt", password)
                salt      = blob[8:24]
                armored   = armor_encode(blob, salt)
                with open(out_path, "w", encoding="utf-8") as fh:
                    fh.write(armored)
                self.after(0, lambda: messagebox.showinfo(
                    "Saved", f"Encrypted note saved to:\n{out_path}"))
            except Exception as exc:
                self.after(0, lambda: messagebox.showerror("Encryption error", str(exc)))
            finally:
                self.after(0, lambda: self._set_busy(False))

        def _on_decrypt_note(self) -> None:
            password = self._password_var.get()
            if not password:
                messagebox.showwarning("No password", "Enter a password.")
                return
            in_path = filedialog.askopenfilename(
                title="Open encrypted note",
                filetypes=[("Fractal Note", f"*{self._NOTE_EXT}"), ("All files", "*.*")],
            )
            if not in_path:
                return
            self._set_busy(True)
            threading.Thread(
                target=self._decrypt_note_worker, args=(in_path, password), daemon=True
            ).start()

        def _decrypt_note_worker(self, in_path: str, password: str) -> None:
            try:
                with open(in_path, "r", encoding="utf-8") as fh:
                    raw = fh.read()
                if raw.strip().startswith("-----BEGIN FRACTAL"):
                    blob = armor_decode(raw)
                else:
                    with open(in_path, "rb") as fh2:
                        blob = fh2.read()
                _name, plaintext = self._cipher.decrypt_v2_bytes(blob, password)
                text = plaintext.decode("utf-8")
                def load():
                    self._clear_placeholder()
                    self._editor.delete("1.0", "end")
                    self._editor.insert("1.0", text)
                    self._on_key_release()
                self.after(0, load)
            except UnicodeDecodeError:
                self.after(0, lambda: messagebox.showerror(
                    "Decode error",
                    "Decrypted bytes are not valid UTF-8. "
                    "The note may not be a text file."))
            except Exception as exc:
                self.after(0, lambda: messagebox.showerror("Decryption error", str(exc)))
            finally:
                self.after(0, lambda: self._set_busy(False))

        def _on_copy_encrypted(self) -> None:
            text = self._get_note_text()
            if not text.strip():
                messagebox.showwarning("Empty note", "The note is empty. Nothing to encrypt.")
                return
            password = self._password_var.get()
            if not password:
                messagebox.showwarning("No password", "Enter a password.")
                return
            self._set_busy(True)
            threading.Thread(
                target=self._copy_worker, args=(text, password), daemon=True
            ).start()

        def _copy_worker(self, text: str, password: str) -> None:
            try:
                plaintext = text.encode("utf-8")
                blob      = self._cipher.encrypt_v2_bytes(plaintext, "note.txt", password)
                salt      = blob[8:24]
                armored   = armor_encode(blob, salt)
                def copy():
                    self.clipboard_clear()
                    self.clipboard_append(armored)
                    messagebox.showinfo("Copied",
                        "ASCII-armored encrypted note copied to clipboard.\n"
                        "Paste anywhere to share.")
                self.after(0, copy)
            except Exception as exc:
                self.after(0, lambda: messagebox.showerror("Encryption error", str(exc)))
            finally:
                self.after(0, lambda: self._set_busy(False))

        def _on_clear(self) -> None:
            if not self._get_note_text().strip():
                return
            if messagebox.askyesno("Clear note",
                                   "Are you sure you want to clear the note?\n"
                                   "This cannot be undone."):
                self._editor.delete("1.0", "end")
                self._show_placeholder()
                self._update_gutter()
                self._update_counter()

        def _set_busy(self, busy: bool) -> None:
            state = "disabled" if busy else "normal"
            for btn in (self._enc_note_btn, self._dec_note_btn,
                        self._copy_btn, self._clear_btn):
                btn.config(state=state)


# ─────────────────────────────────────────────────────────────────────────────
# SHRED CONFIRMATION DIALOG
# ─────────────────────────────────────────────────────────────────────────────

if not _CLI_MODE:
    class ShredConfirmDialog(tk.Toplevel):
        """
        Custom confirmation dialog that requires the user to type SHRED
        before the confirm button becomes active.

        Returns True via `self.confirmed` if the user confirmed.
        """

        def __init__(self, parent, files_info: list) -> None:
            """
            Parameters
            ----------
            parent : tk.Widget
            files_info : list of (path, size_bytes) tuples
            """
            super().__init__(parent)
            self.confirmed = False
            self._files_info = files_info

            self.title("⚠️  Confirm Permanent Deletion")
            self.configure(bg="#1a0a0a")
            self.resizable(False, False)
            self.grab_set()  # modal

            # Border frame
            border = tk.Frame(self, bg=SHRED_RED, padx=2, pady=2)
            border.pack(fill="both", expand=True, padx=4, pady=4)
            inner = tk.Frame(border, bg="#1a0a0a", padx=20, pady=16)
            inner.pack(fill="both", expand=True)

            # Header
            tk.Label(inner, text="⚠️  CONFIRM PERMANENT DELETION",
                     bg="#1a0a0a", fg=SHRED_RED, font=FONT_MONO_XL).pack(anchor="w", pady=(0, 8))

            tk.Label(inner, text="You are about to permanently shred:",
                     bg="#1a0a0a", fg=TEXT, font=FONT_MONO).pack(anchor="w", pady=(0, 6))

            # File list
            for path, size in files_info:
                size_mb = size / (1024 * 1024)
                fname   = os.path.basename(path)
                tk.Label(inner,
                         text=f"  •  {fname}  ({size_mb:.1f} MB)",
                         bg="#1a0a0a", fg="#e0e0ff",
                         font=FONT_MONO_SM, anchor="w").pack(fill="x")

            tk.Frame(inner, bg=BORDER, height=1).pack(fill="x", pady=10)

            tk.Label(inner, text="3-pass DoD overwrite. No recovery possible.",
                     bg="#1a0a0a", fg=WARNING, font=FONT_MONO_SM).pack(anchor="w", pady=(0, 10))

            # SHRED entry
            confirm_row = tk.Frame(inner, bg="#1a0a0a")
            confirm_row.pack(fill="x", pady=(0, 16))
            tk.Label(confirm_row, text="Type SHRED to confirm: ",
                     bg="#1a0a0a", fg=TEXT, font=FONT_MONO).pack(side="left")
            self._shred_var = tk.StringVar()
            self._entry = tk.Entry(
                confirm_row, textvariable=self._shred_var,
                bg="#0a0a0a", fg=SHRED_RED, insertbackground=SHRED_RED,
                font=FONT_MONO_LG, relief="flat", bd=3, width=12,
            )
            self._entry.pack(side="left", padx=6)
            self._shred_var.trace_add("write", self._on_text_change)

            # Buttons
            btn_row = tk.Frame(inner, bg="#1a0a0a")
            btn_row.pack(fill="x")
            tk.Button(
                btn_row, text="Cancel",
                bg=BG_CARD, fg=TEXT, font=FONT_MONO,
                relief="flat", bd=0, cursor="hand2", padx=16, pady=8,
                command=self._on_cancel,
                activebackground=BG_PANEL, activeforeground=TEXT,
            ).pack(side="left")
            self._confirm_btn = tk.Button(
                btn_row, text="🔥 CONFIRM SHRED",
                bg="#3a0a0a", fg=TEXT_DIM, font=FONT_MONO,
                relief="flat", bd=0, cursor="hand2", padx=16, pady=8,
                command=self._on_confirm,
                activebackground=SHRED_RED, activeforeground=BG_DARK,
                state="disabled",
            )
            self._confirm_btn.pack(side="right")

            self._entry.focus_set()
            self.bind("<Return>", self._on_return)
            self.bind("<Escape>", lambda _: self._on_cancel())

            # Centre on parent
            self.update_idletasks()
            pw = parent.winfo_rootx() + parent.winfo_width() // 2
            ph = parent.winfo_rooty() + parent.winfo_height() // 2
            w  = self.winfo_width()
            h  = self.winfo_height()
            self.geometry(f"+{pw - w // 2}+{ph - h // 2}")

        def _on_text_change(self, *_args) -> None:
            if self._shred_var.get() == "SHRED":
                self._confirm_btn.config(
                    state="normal", bg=SHRED_RED, fg=BG_DARK)
            else:
                self._confirm_btn.config(
                    state="disabled", bg="#3a0a0a", fg=TEXT_DIM)

        def _on_confirm(self) -> None:
            if self._shred_var.get() == "SHRED":
                self.confirmed = True
                self.destroy()

        def _on_cancel(self) -> None:
            self.confirmed = False
            self.destroy()

        def _on_return(self, _event=None) -> None:
            if self._shred_var.get() == "SHRED":
                self._on_confirm()


# ─────────────────────────────────────────────────────────────────────────────
# TAB 5: SECURE FILE SHREDDER
# ─────────────────────────────────────────────────────────────────────────────

if not _CLI_MODE:
    # Global in-memory cooldown dict: filepath -> datetime of last shred
    # Protected by _shred_lock so both GUI and worker threads can safely access it.
    _shred_cooldowns: dict = {}
    _shred_lock = threading.Lock()   # guards _shred_cooldowns
    _COOLDOWN_SECONDS = 300  # 5 minutes

    class ShredderTab(tk.Frame):
        """
        Tab 5: Secure File Shredder.

        DoD 5220.22-M inspired 3-pass overwrite with a mandatory 5-minute
        per-file cooldown enforced after each shred.
        """

        def __init__(self, parent) -> None:
            super().__init__(parent, bg=BG_PANEL)
            # Internal list of (path, shredded_flag) tuples
            self._files: list = []          # list of str paths
            self._shredded: dict = {}       # path → True if shredded this session
            self._busy  = False
            self._cooldown_job = None
            self._dnd_pulse_job = None
            self._dnd_phase = 0.0
            self._build_ui()
            self._start_cooldown_timer()

        # ── UI construction ───────────────────────────────────────────────────

        def _build_ui(self) -> None:
            # ── Warning Banner ────────────────────────────────────────────────
            banner = tk.Frame(self, bg=SHRED_BG, pady=6)
            banner.pack(fill="x", padx=0, pady=0)
            tk.Label(
                banner,
                text="⚠️   PERMANENT DELETION — Files cannot be recovered after shredding",
                bg=SHRED_BG, fg=SHRED_RED,
                font=("Consolas", 11, "bold"),
                padx=16, pady=4,
            ).pack(anchor="w")

            # ── Main content ──────────────────────────────────────────────────
            content = tk.Frame(self, bg=BG_PANEL)
            content.pack(fill="both", expand=True, padx=12, pady=8)

            # Left: file list
            left = tk.Frame(content, bg=BG_CARD)
            left.pack(side="left", fill="both", expand=True, padx=(0, 8))

            title_row = tk.Frame(left, bg=BG_CARD)
            title_row.pack(fill="x", padx=8, pady=(8, 2))
            tk.Label(title_row, text="  FILES TO SHRED", bg=BG_CARD, fg=SHRED_RED,
                     font=FONT_TITLE).pack(side="left")
            if DND_AVAILABLE:
                tk.Label(title_row, text="  ⤵ Drop files here",
                         bg=BG_CARD, fg=TEXT_DIM, font=FONT_MONO_SM).pack(side="right")

            # Listbox with drop support
            self._drop_border = tk.Frame(left, bg=BORDER, padx=1, pady=1)
            self._drop_border.pack(fill="both", expand=True, padx=8, pady=(0, 4))
            lb_frame = tk.Frame(self._drop_border, bg="#0a0a0a")
            lb_frame.pack(fill="both", expand=True)
            scrollbar = tk.Scrollbar(lb_frame, bg=BG_DARK)
            scrollbar.pack(side="right", fill="y")
            self._listbox = tk.Listbox(
                lb_frame, bg="#0a0a0a", fg=TEXT,
                selectbackground="#2a0a0a", selectforeground=SHRED_RED,
                font=FONT_MONO_SM, relief="flat", bd=0,
                highlightthickness=0, yscrollcommand=scrollbar.set,
                activestyle="none",
            )
            self._listbox.pack(side="left", fill="both", expand=True)
            scrollbar.config(command=self._listbox.yview)

            if DND_AVAILABLE:
                self._listbox.drop_target_register(DND_FILES)
                self._listbox.dnd_bind("<<Drop>>",      self._on_dnd_drop)
                self._listbox.dnd_bind("<<DragEnter>>", self._on_dnd_enter)
                self._listbox.dnd_bind("<<DragLeave>>", self._on_dnd_leave)

            # File list buttons
            btn_row = tk.Frame(left, bg=BG_CARD)
            btn_row.pack(fill="x", padx=8, pady=(2, 8))
            self._btn_add   = self._small_btn(btn_row, "+ Add Files", self._add_files)
            self._btn_rem   = self._small_btn(btn_row, "✕ Remove Selected", self._remove_selected)
            self._btn_clear = self._small_btn(btn_row, "🗑 Clear List", self._clear_list)
            Tooltip(self._btn_add,   "Add files to the shred queue.")
            Tooltip(self._btn_rem,   "Remove selected entry from the list (no shred).")
            Tooltip(self._btn_clear, "Clear all entries from the list (no shred).")

            # Right: controls + log
            right = tk.Frame(content, bg=BG_PANEL)
            right.pack(side="right", fill="y")

            ctrl = tk.Frame(right, bg=BG_CARD, padx=12, pady=10)
            ctrl.pack(fill="x", pady=(0, 8))

            # Per-file progress
            tk.Label(ctrl, text="FILE PROGRESS", bg=BG_CARD, fg=TEXT_DIM,
                     font=FONT_MONO_SM, anchor="w").pack(fill="x")
            self._file_progress = ttk.Progressbar(
                ctrl, orient="horizontal", mode="determinate", maximum=100)
            self._file_progress.pack(fill="x", pady=(2, 6))
            self._file_lbl = tk.Label(ctrl, text="—", bg=BG_CARD, fg=TEXT_DIM,
                                       font=FONT_MONO_SM, anchor="w")
            self._file_lbl.pack(fill="x")

            # Overall progress
            tk.Label(ctrl, text="OVERALL PROGRESS", bg=BG_CARD, fg=TEXT_DIM,
                     font=FONT_MONO_SM, anchor="w").pack(fill="x", pady=(10, 0))
            self._overall_progress = ttk.Progressbar(
                ctrl, orient="horizontal", mode="determinate", maximum=100)
            self._overall_progress.pack(fill="x", pady=(2, 6))

            # Action buttons
            self._shred_sel_btn = tk.Button(
                ctrl, text="🔥 SHRED SELECTED",
                bg=SHRED_RED, fg=BG_DARK, font=FONT_MONO_LG,
                relief="flat", bd=0, cursor="hand2", padx=8, pady=10,
                command=self._on_shred_selected,
                activebackground="#cc3355", activeforeground=BG_DARK,
            )
            self._shred_sel_btn.pack(fill="x", pady=(8, 4))
            self._shred_all_btn = tk.Button(
                ctrl, text="🔥 SHRED ALL",
                bg="#aa2233", fg=BG_DARK, font=FONT_MONO_LG,
                relief="flat", bd=0, cursor="hand2", padx=8, pady=10,
                command=self._on_shred_all,
                activebackground=SHRED_RED, activeforeground=BG_DARK,
            )
            self._shred_all_btn.pack(fill="x")
            Tooltip(self._shred_sel_btn,
                    "Securely shred selected files (3-pass DoD). "
                    "Disabled if any selected file is on cooldown.")
            Tooltip(self._shred_all_btn,
                    "Shred all listed files. Only active if ALL files are ready.")

            # Log console
            tk.Label(right, text="  SHRED LOG", bg=BG_PANEL, fg=TEXT_DIM,
                     font=FONT_MONO_SM, anchor="w").pack(fill="x", pady=(4, 0))
            self._log = LogConsole(right)
            self._log.pack(fill="both", expand=True)

        # ── Widget factories ──────────────────────────────────────────────────

        @staticmethod
        def _small_btn(parent, text, cmd):
            btn = tk.Button(
                parent, text=text, command=cmd,
                bg=BG_DARK, fg=TEXT_DIM, font=FONT_MONO_SM,
                relief="flat", bd=0, cursor="hand2", padx=6, pady=3,
                activebackground=BG_PANEL, activeforeground=SHRED_RED,
            )
            btn.pack(side="left", padx=2)
            return btn

        # ── Drag & drop ───────────────────────────────────────────────────────

        def _on_dnd_drop(self, event) -> None:
            self._stop_dnd_pulse()
            raw   = event.data.strip()
            paths = []
            if raw.startswith("{"):
                import re
                paths = re.findall(r"\{([^}]+)\}|(\S+)", raw)
                paths = [a or b for a, b in paths]
            else:
                paths = raw.split()
            for p in paths:
                p = p.strip().strip("{}")
                if p:
                    self._add_file(p)

        def _on_dnd_enter(self, _event=None) -> None:
            self._dnd_phase = 0.0
            self._dnd_pulse()

        def _on_dnd_leave(self, _event=None) -> None:
            self._stop_dnd_pulse()

        def _dnd_pulse(self) -> None:
            phase  = (math.sin(self._dnd_phase) + 1) / 2
            r = int(0x2a + (0xee - 0x2a) * phase)
            g = int(0x0a + (0x00 - 0x0a) * phase)
            b = int(0x0a + (0x00 - 0x0a) * phase)
            colour = f"#{r:02x}{g:02x}{b:02x}"
            if hasattr(self, "_drop_border"):
                self._drop_border.config(bg=colour)
            self._dnd_phase += 0.2
            self._dnd_pulse_job = self.after(40, self._dnd_pulse)

        def _stop_dnd_pulse(self) -> None:
            if self._dnd_pulse_job:
                self.after_cancel(self._dnd_pulse_job)
                self._dnd_pulse_job = None
            if hasattr(self, "_drop_border"):
                self._drop_border.config(bg=BORDER)

        # ── File management ───────────────────────────────────────────────────

        def _add_files(self) -> None:
            paths = filedialog.askopenfilenames(title="Select files to shred")
            for p in paths:
                self._add_file(p)

        def _add_file(self, path: str) -> None:
            """Add a single file, checking for cooldown / existence."""
            path = os.path.abspath(path)

            if path in _shred_cooldowns:
                with _shred_lock:
                    cd = _shred_cooldowns.get(path)
                elapsed = (datetime.datetime.now() - cd).total_seconds() if cd else _COOLDOWN_SECONDS
                remaining = _COOLDOWN_SECONDS - elapsed
                if remaining > 0:
                    mins = int(remaining // 60)
                    secs = int(remaining % 60)
                    messagebox.showwarning(
                        "Cooldown Active",
                        f"This file was recently shredded and no longer exists.\n"
                        f"Cooldown: {mins}m {secs}s remaining.\n\n{path}"
                    )
                    return

            if not os.path.isfile(path):
                messagebox.showwarning("Not a file",
                                       f"The path is not a regular file:\n{path}")
                return

            if path in self._files:
                return  # already in list

            self._files.append(path)
            self._shredded[path] = False
            self._refresh_listbox()

        def _remove_selected(self) -> None:
            sel = self._listbox.curselection()
            if sel:
                idx = sel[0]
                path = self._files.pop(idx)
                self._shredded.pop(path, None)
                self._refresh_listbox()

        def _clear_list(self) -> None:
            self._files.clear()
            self._shredded.clear()
            self._listbox.delete(0, "end")

        # ── Cooldown display ──────────────────────────────────────────────────

        def _start_cooldown_timer(self) -> None:
            """Schedule recurring 1-second updates for cooldown display."""
            self._tick_cooldowns()

        def _tick_cooldowns(self) -> None:
            """Update listbox entries and remove expired cooldown entries."""
            self._refresh_listbox()
            # Remove entries whose cooldown has expired AND they are shredded
            to_remove = []
            for path in list(self._files):
                if self._shredded.get(path):
                    with _shred_lock:
                        cd = _shred_cooldowns.get(path)
                    if cd:
                        elapsed = (datetime.datetime.now() - cd).total_seconds()
                        if elapsed >= _COOLDOWN_SECONDS:
                            to_remove.append(path)
            for path in to_remove:
                self._files.remove(path)
                self._shredded.pop(path, None)
                with _shred_lock:
                    _shred_cooldowns.pop(path, None)
            if to_remove:
                self._refresh_listbox()

            self._cooldown_job = self.after(1000, self._tick_cooldowns)

        def _get_status_text(self, path: str) -> str:
            """Return status column text for a path."""
            fname   = os.path.basename(path)
            try:
                size = os.path.getsize(path) if os.path.isfile(path) else 0
                size_mb = size / (1024 * 1024)
            except OSError:
                size_mb = 0.0

            with _shred_lock:
                cd_shredded = _shred_cooldowns.get(path) if self._shredded.get(path) else None
                cd_waiting  = _shred_cooldowns.get(path) if not self._shredded.get(path) else None

            if self._shredded.get(path):
                if cd_shredded:
                    elapsed   = (datetime.datetime.now() - cd_shredded).total_seconds()
                    remaining = _COOLDOWN_SECONDS - elapsed
                    if remaining > 0:
                        mins = int(remaining // 60)
                        secs = int(remaining % 60)
                        return (f"{fname}  |  {size_mb:.2f} MB  |  "
                                f"[OK] Shredded -- cooldown: {mins}:{secs:02d}")
                return f"{fname}  |  [OK] Shredded"
            else:
                if cd_waiting:
                    elapsed   = (datetime.datetime.now() - cd_waiting).total_seconds()
                    remaining = _COOLDOWN_SECONDS - elapsed
                    if remaining > 0:
                        mins = int(remaining // 60)
                        secs = int(remaining % 60)
                        return (f"{fname}  |  {size_mb:.2f} MB  |  "
                                f"[~] Cooldown: {mins}:{secs:02d}")
                return f"{fname}  |  {size_mb:.2f} MB  |  [OK] Ready"

        def _refresh_listbox(self) -> None:
            """Repopulate the listbox with current status."""
            self._listbox.delete(0, "end")
            for path in self._files:
                label = self._get_status_text(path)
                self._listbox.insert("end", label)
                if self._shredded.get(path):
                    # Dim shredded entries
                    self._listbox.itemconfig("end", fg=TEXT_DIM)

        def _is_on_cooldown(self, path: str) -> bool:
            """Return True if the path currently has an active cooldown."""
            with _shred_lock:
                cd = _shred_cooldowns.get(path)
            if cd:
                elapsed = (datetime.datetime.now() - cd).total_seconds()
                return elapsed < _COOLDOWN_SECONDS
            return False

        # ── Shred actions ─────────────────────────────────────────────────────

        def _on_shred_selected(self) -> None:
            sel = self._listbox.curselection()
            if not sel:
                messagebox.showwarning("No selection", "Select files to shred.")
                return
            targets = [self._files[i] for i in sel
                       if not self._is_on_cooldown(self._files[i])
                       and not self._shredded.get(self._files[i])]
            if not targets:
                messagebox.showwarning("Cooldown",
                                       "All selected files are on cooldown or already shredded.")
                return
            self.queue_shred_with_confirm(targets)

        def _on_shred_all(self) -> None:
            targets = [p for p in self._files
                       if not self._is_on_cooldown(p)
                       and not self._shredded.get(p)
                       and os.path.isfile(p)]
            if not targets:
                messagebox.showwarning("Nothing to shred",
                                       "No files are ready for shredding.")
                return
            self.queue_shred_with_confirm(targets)

        def queue_shred_with_confirm(self, paths: list) -> None:
            """
            Show the confirmation dialog then shred if confirmed.
            Can be called externally (from EncryptTab shred-after-encrypt).
            """
            files_info = []
            for p in paths:
                try:
                    sz = os.path.getsize(p) if os.path.isfile(p) else 0
                except OSError:
                    sz = 0
                files_info.append((p, sz))

            dlg = ShredConfirmDialog(self.winfo_toplevel(), files_info)
            self.wait_window(dlg)

            if dlg.confirmed:
                self._set_busy(True)
                threading.Thread(
                    target=self._shred_worker,
                    args=(paths,),
                    daemon=True,
                ).start()

        def _shred_worker(self, paths: list) -> None:
            """Background worker: shred all files in sequence."""
            total   = len(paths)
            success = 0

            for idx, path in enumerate(paths):
                fname = os.path.basename(path)

                if not os.path.isfile(path):
                    self.after(0, lambda f=fname: self._log.error(
                        f"{f} — file not found, skipping"))
                    continue

                try:
                    file_size = os.path.getsize(path)
                    size_mb   = file_size / (1024 * 1024)

                    def _progress(p_num, p_total, frac, _path=path, _fname=fname):
                        pass_names = {1: "zeros", 2: "ones"}
                        pname = pass_names.get(p_num, "random")
                        self.after(0, lambda: self._file_progress.__setitem__("value", frac * 100))
                        self.after(0, lambda p=p_num, pt=p_total, n=pname, f=_fname:
                                   self._file_lbl.config(
                                       text=f"{f}  Pass {p}/{pt} ({n})"))

                    def _log_cb(msg: str):
                        self.after(0, lambda m=msg: self._log.info(m))

                    shred_file(path, passes=3, progress_cb=_progress, log_cb=_log_cb)

                    # Record cooldown + mark shredded (lock guards the shared dict)
                    with _shred_lock:
                        _shred_cooldowns[path] = datetime.datetime.now()
                    self._shredded[path] = True
                    success += 1

                    next_time = (datetime.datetime.now() +
                                 datetime.timedelta(seconds=_COOLDOWN_SECONDS))
                    self.after(0, lambda f=fname, mb=size_mb, nt=next_time:
                               self._log.success(
                                   f"✅ {f} permanently deleted "
                                   f"(3 passes, {mb:.2f} MB)"))
                    self.after(0, lambda nt=next_time:
                               self._log.warning(
                                   f"⏳ Cooldown started — next shred available at "
                                   f"{nt.strftime('%H:%M:%S')}"))

                except Exception as exc:
                    self.after(0, lambda f=fname, e=str(exc):
                               self._log.error(f"✕ {f}: {e}"))

                # Update overall progress
                overall = (idx + 1) / total * 100
                self.after(0, lambda v=overall: self._overall_progress.__setitem__(
                    "value", v))

            self.after(0, lambda: self._on_shred_complete(success, total))

        def _on_shred_complete(self, success: int, total: int) -> None:
            self._set_busy(False)
            self._file_progress["value"] = 0
            self._overall_progress["value"] = 0
            self._file_lbl.config(text="—")
            if success == total:
                self._log.success(f"Batch shred complete: {success}/{total} files shredded.")
            else:
                self._log.warning(f"Batch shred: {success}/{total} files shredded. "
                                   f"{total - success} error(s).")

        def _set_busy(self, busy: bool) -> None:
            self._busy = busy
            state = "disabled" if busy else "normal"
            self._shred_sel_btn.config(state=state)
            self._shred_all_btn.config(state=state)
            self._btn_add.config(state=state)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN APPLICATION
# ─────────────────────────────────────────────────────────────────────────────

if not _CLI_MODE:
    class FractalCryptApp:
        """
        Root application controller.

        Creates the main window (TkinterDnD.Tk if drag & drop available,
        otherwise plain tk.Tk), applies the dark fractal theme, builds the
        five-tab notebook, and wires up shared state across all tabs.
        """

        def __init__(self) -> None:
            if DND_AVAILABLE:
                self._root = TkinterDnD.Tk()
            else:
                self._root = tk.Tk()

            self._root.title("🔮 FractalCrypt — Fractal File Encryption")
            self._root.geometry("960x720")
            self._root.resizable(False, False)
            self._root.configure(bg=BG_DARK)

            self._set_icon()
            self._password_var = tk.StringVar()
            self._apply_theme()
            self._build_header()
            self._build_notebook()

            # Wire the log console into the encrypt tab's log area
            self._log.pack(fill="both", expand=True,
                           in_=self._enc_tab, padx=12, pady=(0, 10))

        # ── Icon ──────────────────────────────────────────────────────────────

        def _set_icon(self) -> None:
            try:
                size = 32
                img  = tk.PhotoImage(width=size, height=size)
                for py in range(size):
                    for px in range(size):
                        zr = (px / size) * 3.5 - 2.5
                        zi = (py / size) * 2.5 - 1.25
                        cr, ci = zr, zi
                        n = 0
                        for n in range(20):
                            if zr * zr + zi * zi > 4:
                                break
                            zr, zi = zr * zr - zi * zi + cr, 2 * zr * zi + ci
                        t = n / 20
                        g = int(255 * t)
                        b = int(204 * (1 - t))
                        img.put(f"#00{g:02x}{b:02x}", (px, py))
                self._root.iconphoto(True, img)
            except Exception:
                pass

        # ── Theme ─────────────────────────────────────────────────────────────

        def _apply_theme(self) -> None:
            style = ttk.Style(self._root)
            style.theme_use("default")
            style.configure("TNotebook", background=BG_DARK,
                            borderwidth=0, tabmargins=[4, 4, 0, 0])
            style.configure("TNotebook.Tab", background=BG_PANEL,
                            foreground=TEXT_DIM, font=FONT_MONO,
                            padding=[14, 7], borderwidth=0)
            style.map("TNotebook.Tab",
                      background=[("selected", BG_CARD)],
                      foreground=[("selected", ACCENT)])
            style.configure("TProgressbar", troughcolor=BG_DARK,
                            background=ACCENT, borderwidth=0, thickness=6)

        # ── Header ────────────────────────────────────────────────────────────

        def _build_header(self) -> None:
            header = tk.Frame(self._root, bg=BG_DARK, pady=8)
            header.pack(fill="x", padx=16)
            tk.Label(header, text="🔮  FractalCrypt",
                     bg=BG_DARK, fg=ACCENT,
                     font=("Consolas", 18, "bold")).pack(side="left")
            tk.Label(header, text=" — Fractal-Based File Encryption",
                     bg=BG_DARK, fg=TEXT_DIM,
                     font=("Consolas", 12)).pack(side="left")
            badge_text = "  v4.0  PBKDF2+Salt+Shredder"
            if DND_AVAILABLE:
                badge_text += " | DnD"
            tk.Label(header, text=badge_text + "  ",
                     bg=BG_CARD, fg=ACCENT,
                     font=FONT_MONO_SM, padx=6, pady=2).pack(side="right")
            tk.Frame(self._root, bg=BORDER, height=1).pack(fill="x", padx=8)

        # ── Notebook ──────────────────────────────────────────────────────────

        def _build_notebook(self) -> None:
            notebook = ttk.Notebook(self._root)
            notebook.pack(fill="both", expand=True, padx=8, pady=8)

            self._log = LogConsole(self._root)

            # Tab 5: Shredder (built first so Tab 1 can reference it)
            shredder_tab = ShredderTab(notebook)

            # Tab 1: Encrypt / Decrypt — pass shredder ref
            self._enc_tab = EncryptTab(notebook, self._password_var,
                                        self._log, shredder_tab_ref=shredder_tab)
            notebook.add(self._enc_tab, text="  🔒  Encrypt / Decrypt  ")

            # Tab 2: Key Visualizer
            vis_tab = VisualizerTab(notebook, self._password_var, self._log)
            notebook.add(vis_tab, text="  🔮  Key Visualizer  ")

            # Tab 3: Keystream Analysis
            ana_tab = AnalysisTab(notebook, self._password_var)
            notebook.add(ana_tab, text="  📊  Keystream Analysis  ")

            # Tab 4: Secure Notes
            notes_tab = SecureNotesTab(notebook, self._password_var)
            notebook.add(notes_tab, text="  📝  Secure Notes  ")

            # Tab 5: Shredder (add after Tab 4 to get correct order)
            notebook.add(shredder_tab, text="  🗑️  Shredder  ")

        # ── Entry point ───────────────────────────────────────────────────────

        def run(self) -> None:
            self._root.mainloop()


# ─────────────────────────────────────────────────────────────────────────────
# CLI MODE  (run_cli)
# ─────────────────────────────────────────────────────────────────────────────

def run_cli() -> None:
    """
    CLI entry point.  Uses argparse with subcommands:
      encrypt, decrypt, shred, analyze
    """
    import argparse
    import getpass

    parser = argparse.ArgumentParser(
        prog="fractal_gui.py",
        description="FractalCrypt -- Fractal-Based File Encryption CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python fractal_gui.py encrypt input.pdf output.fractal --password hunter2
  python fractal_gui.py encrypt input.pdf output.fractal.asc --armor --shred-original
  python fractal_gui.py decrypt output.fractal decrypted.pdf --password hunter2
  python fractal_gui.py shred secret.docx notes.txt --passes 3
  python fractal_gui.py analyze --password hunter2 --bytes 2048
        """,
    )
    sub = parser.add_subparsers(dest="command")

    # ── encrypt ───────────────────────────────────────────────────────────────
    enc_p = sub.add_parser("encrypt", help="Encrypt a file")
    enc_p.add_argument("input",  help="Input file path")
    enc_p.add_argument("output", help="Output .fractal file path")
    enc_p.add_argument("--password", "-p", default=None,
                       help="Encryption password (prompted if omitted)")
    enc_p.add_argument("--armor", action="store_true",
                       help="Wrap output in ASCII armor (.asc)")
    enc_p.add_argument("--shred-original", action="store_true",
                       help="Shred the input file after successful encryption")

    # ── decrypt ───────────────────────────────────────────────────────────────
    dec_p = sub.add_parser("decrypt", help="Decrypt a .fractal file")
    dec_p.add_argument("input",  help="Input .fractal file path")
    dec_p.add_argument("output", help="Output decrypted file path")
    dec_p.add_argument("--password", "-p", default=None,
                       help="Decryption password (prompted if omitted)")

    # ── shred ─────────────────────────────────────────────────────────────────
    shr_p = sub.add_parser("shred", help="Securely delete files")
    shr_p.add_argument("files", nargs="+", help="Files to shred")
    shr_p.add_argument("--passes", type=int, default=3,
                       help="Number of overwrite passes (1–7, default: 3)")
    shr_p.add_argument("--no-confirm", action="store_true",
                       help="Skip confirmation prompt (for scripting)")

    # ── analyze ───────────────────────────────────────────────────────────────
    ana_p = sub.add_parser("analyze",
                            help="Analyze keystream randomness statistics")
    ana_p.add_argument("--password", "-p", default=None,
                       help="Password to analyze (prompted if omitted)")
    ana_p.add_argument("--bytes", type=int, default=1024,
                       help="Keystream length to analyze (default: 1024)")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    # ─────────────────────────────────────────────────────────────────────────

    if args.command == "encrypt":
        password = args.password or getpass.getpass("Password: ")
        print(f"Encrypting {args.input!r}...", end=" ", flush=True)
        try:
            cipher = FractalCipherV2(verbose=False)
            if args.armor:
                import tempfile as _tmp
                with _tmp.NamedTemporaryFile(suffix=".fractal", delete=False) as tf:
                    tmp_path = tf.name
                try:
                    salt = cipher.encrypt_v2(args.input, tmp_path, password)
                    with open(tmp_path, "rb") as fh:
                        blob = fh.read()
                    text = armor_encode(blob, salt)
                    out  = args.output if args.output.endswith(".asc") else args.output + ".asc"
                    with open(out, "w", encoding="utf-8") as fh:
                        fh.write(text)
                    args.output = out
                finally:
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass
            else:
                cipher.encrypt_v2(args.input, args.output, password)

            print(f"[OK] Done -> {args.output}")

            if args.shred_original:
                print(f"Shredding original {args.input!r}...", end=" ", flush=True)
                shred_file(args.input, passes=3,
                           log_cb=lambda m: print(f"  {m}"))
                print("[OK] Shredded")

        except Exception as exc:
            print(f"\n[!] Error: {exc}", file=sys.stderr)
            sys.exit(1)

    # ─────────────────────────────────────────────────────────────────────────

    elif args.command == "decrypt":
        password = args.password or getpass.getpass("Password: ")
        print(f"Decrypting {args.input!r}...", end=" ", flush=True)
        try:
            cipher = FractalCipherV2(verbose=False)
            if is_armored(args.input):
                print("(ASCII armor detected)", end=" ", flush=True)
                with open(args.input, "r", encoding="utf-8") as fh:
                    text = fh.read()
                blob = armor_decode(text)
                import tempfile as _tmp
                with _tmp.NamedTemporaryFile(suffix=".fractal", delete=False) as tf:
                    tmp_path = tf.name
                    tf.write(blob)
                try:
                    cipher.decrypt_v2(tmp_path, args.output, password)
                finally:
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass
            else:
                cipher.decrypt_v2(args.input, args.output, password)
            print(f"[OK] Done -> {args.output}")
        except Exception as exc:
            print(f"\n[!] Error: {exc}", file=sys.stderr)
            sys.exit(1)

    # ─────────────────────────────────────────────────────────────────────────

    elif args.command == "shred":
        passes = max(1, min(args.passes, 7))
        targets = []
        for p in args.files:
            if not os.path.isfile(p):
                print(f"[!] Not a file: {p}", file=sys.stderr)
            else:
                targets.append(p)

        if not targets:
            print("No valid files to shred.", file=sys.stderr)
            sys.exit(1)

        if not args.no_confirm:
            print("\nFiles to be permanently shredded:")
            for p in targets:
                sz = os.path.getsize(p) / (1024 * 1024)
                print(f"  * {os.path.basename(p)}  ({sz:.2f} MB)")
            print(f"\n{passes}-pass DoD overwrite. No recovery possible.")
            answer = input("Type SHRED to confirm: ")
            if answer != "SHRED":
                print("Shred cancelled.")
                sys.exit(0)

        errors = 0
        for p in targets:
            try:
                shred_file(
                    p, passes=passes,
                    progress_cb=lambda p_num, p_tot, frac, f=os.path.basename(p):
                        print(f"\r  {f}  Pass {p_num}/{p_tot}  "
                              f"[{'#' * int(frac*20):<20}] {frac*100:.0f}%",
                              end="", flush=True),
                    log_cb=lambda m: print(f"\n  {m}"),
                )
                print()  # newline after progress bar
            except Exception as exc:
                print(f"\n[!] {os.path.basename(p)}: {exc}", file=sys.stderr)
                errors += 1

        if errors:
            sys.exit(1)

    # ─────────────────────────────────────────────────────────────────────────

    elif args.command == "analyze":
        password = args.password or getpass.getpass("Password: ")
        n_bytes  = max(64, args.bytes)
        NUM_BINS = 16

        print(f"\nKeystream Analysis ({n_bytes} bytes, password: {'*' * len(password)})")
        print("-" * 60)

        try:
            dummy_salt    = bytes(16)
            stretched_key = stretch_password(password, dummy_salt)
            engine        = FractalKeyEngine()
            keystream     = engine.mandelbrot_keystream(stretched_key, n_bytes)

            bin_size = 256 // NUM_BINS
            counts   = [0] * NUM_BINS
            for b in keystream:
                counts[b // bin_size] += 1

            max_count = max(counts)
            BAR_W     = 30

            for i, cnt in enumerate(counts):
                lo    = i * bin_size
                hi    = lo + bin_size - 1
                bar   = int(cnt / max_count * BAR_W)
                empty = BAR_W - bar
                print(f"Bin {lo:03d}-{hi:03d} | {'#' * bar}{'.' * empty} | {cnt} bytes")

            # Statistics
            expected = n_bytes / NUM_BINS
            chi2 = sum((o - expected) ** 2 / expected for o in counts)

            freq = [0] * 256
            for bv in keystream:
                freq[bv] += 1
            entropy = -sum((f / n_bytes) * math.log2(f / n_bytes)
                           for f in freq if f > 0)

            ideal_chi2 = NUM_BINS - 1  # ~15 for 16 bins

            print("-" * 60)
            print(f"Chi-squared  : {chi2:.1f}  (ideal: {ideal_chi2:.1f})")
            print(f"Shannon      : {entropy:.4f} bits/byte  (max: 8.0)")

            if chi2 < 20 and entropy > 7.8:
                verdict = "Excellent randomness"
            elif chi2 < 40 and entropy > 7.5:
                verdict = "Good randomness"
            else:
                verdict = "Weak randomness"
            print(f"Verdict      : {verdict}")

        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# GUI ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def run_gui() -> None:
    """Launch the Tkinter GUI application."""
    app = FractalCryptApp()
    app.run()


# ─────────────────────────────────────────────────────────────────────────────
# DUAL MODE DISPATCH
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if _CLI_MODE:
        run_cli()
    else:
        run_gui()
