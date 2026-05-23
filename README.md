<div align="center">

# 🔮 FractalCrypt

### Military-grade file encryption powered by fractal mathematics

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Mac%20%7C%20Linux-lightgrey?style=for-the-badge)]()
[![Security](https://img.shields.io/badge/Encryption-Fractal%20Stream%20Cipher-red?style=for-the-badge)]()

[⬇️ Windows](#-download) • [⬇️ macOS](#-download) • [⬇️ Linux](#-download) • [📖 Docs](#usage)

<img src="docs/screenshot.png" alt="FractalCrypt Screenshot" width="860"/>

</div>

---

<div align="center">
<pre>
┌─────────────────────────────────────────────────────────────┐
│  🔮 FractalCrypt — Fractal File Encryption          _ □ ✕  │
├─────────────────────────────────────────────────────────────┤
│  [🔒 Encrypt/Decrypt]  [🔑 Visualizer]  [📊 Analysis]      │
│            [📝 Notes]  [🗑️  Shredder]                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Files:  document.pdf                        🟢 Ready      │
│          report.xlsx                         🟢 Ready      │
│                                                             │
│  Password: ••••••••••••                      [👁]          │
│  Output:   /home/user/encrypted/             [Browse]      │
│                                                             │
│  ☑ ASCII Armor   ☐ Folder Mode   ☐ Shred original         │
│                                                             │
│  [      🔒 ENCRYPT      ]    [      🔓 DECRYPT      ]      │
├─────────────────────────────────────────────────────────────┤
│  [12:34:01] ✅ document.pdf → document.fractal             │
│  [12:34:02] ✅ HMAC-SHA256 integrity tag written           │
└─────────────────────────────────────────────────────────────┘
</pre>
</div>

---

## 📥 Download

> Pre-built executables — no Python installation required.

| Platform | Download | Requirements |
|----------|----------|--------------|
| 🪟 Windows | [FractalCrypt-windows.exe](https://github.com/SiddharthSeng/FractalCrypt/releases/latest) | Windows 10/11, 64-bit |
| 🍎 macOS | [FractalCrypt-macos](https://github.com/SiddharthSeng/FractalCrypt/releases/latest) | macOS 11+, Intel + Apple Silicon |
| 🐧 Linux | [FractalCrypt-linux](https://github.com/SiddharthSeng/FractalCrypt/releases/latest) | Ubuntu 20.04+, Debian, Fedora |

### First launch — macOS
```bash
xattr -cr FractalCrypt-macos
chmod +x FractalCrypt-macos
./FractalCrypt-macos
```

### First launch — Linux
```bash
chmod +x FractalCrypt-linux
./FractalCrypt-linux
```

### First launch — Windows
Click **More info** → **Run anyway** on the SmartScreen prompt.

### Build from source
```bash
pip install Pillow tkinterdnd2 pyinstaller
python fractal_build.py
```

---

## What is FractalCrypt?

FractalCrypt is a desktop file encryption tool that protects your files using a
custom stream cipher driven by fractal mathematics. Drop in any file — PDF, photo,
archive, document — enter a password, and get a cryptographically encrypted
`.fractal` file that can only be opened with the correct password. A companion CLI
makes it scriptable on any platform.

The cipher derives its keystream from **Mandelbrot set escape-time values** and
builds a per-password **Julia set orbit-trap S-Box** for non-linear byte substitution.
Both operations are seeded by a PBKDF2-HMAC-SHA256 stretched key (200,000 iterations)
with a unique 16-byte random salt per encryption, meaning the same file encrypted
twice produces completely different ciphertext. HMAC-SHA256 guarantees that any
tampering — even a single flipped bit — is detected on decryption before any output
is written.

FractalCrypt is designed for developers, privacy-conscious users, students of applied
cryptography, and anyone who wants a transparent, auditable encryption tool they can
actually read and verify. It ships with a **Key Visualizer** that renders your password
as a unique Mandelbrot + Julia fractal image, a **Keystream Analyzer** with chi-squared
and Shannon entropy statistics, a **Secure Notes** editor, and a **DoD 3-pass File
Shredder** with a mandatory 5-minute cooldown to prevent accidental mass deletion.

---

## ✨ Features

### 🔒 Tab 1 — Encrypt / Decrypt
- Multi-file and folder encryption in one click
- PBKDF2-HMAC-SHA256 key stretching (200,000 iterations) per encryption
- Unique 16-byte random salt — same password + same file → different ciphertext every time
- HMAC-SHA256 integrity verification — tamper-detection on every decryption
- **ASCII Armor mode** — wraps binary output in a PGP-style `.fractal.asc` text envelope, safe to paste in emails or chat
- **Folder mode** — zips an entire folder then encrypts into a single file
- **Shred original after encrypting** checkbox — triggers the 3-pass DoD shredder on source files after successful encryption
- Drag & Drop file support (via `tkinterdnd2`, with graceful fallback)
- Password strength meter with entropy estimate
- Per-file progress bar

### 🔮 Tab 2 — Key Visualizer
- Renders Mandelbrot and Julia fractal images seeded by your password
- Visual key fingerprint: tiny password change → completely different fractal
- **Export PNG** — 800×400 key fingerprint image with SHA-256 hash overlay and timestamp
- Live password strength meter

### 📊 Tab 3 — Keystream Analysis
- Generates N bytes of fractal keystream and plots byte distribution histogram
- Chi-squared uniformity test (lower = better, ideal ≈ 15 for 16 bins)
- Shannon entropy (max = 8.0 bits/byte for perfect randomness)
- Pass / Fail verdict with color coding

### 📝 Tab 4 — Secure Notes
- Encrypted text note editor with syntax highlighting (# headings, > quotes)
- **Encrypt Note** → saves as a `.fractal.note` file
- **Decrypt Note** → opens and decrypts any `.fractal.note`
- **Copy Encrypted** → encrypts in-memory and copies ASCII armor to clipboard
- Character and estimated encrypted-size counter

### 🗑️ Tab 5 — Secure File Shredder
- DoD 5220.22-M inspired 3-pass overwrite: zeros → ones → `os.urandom`
- Each pass calls `flush()` + `os.fsync()` — writes forced to disk
- **5-minute cooldown** per file — prevents accidental mass deletion
- Live M:SS cooldown countdown in the file list
- Custom SHRED confirmation dialog — type `SHRED` to unlock the confirm button
- Drag & Drop support for the shred queue
- Per-file and overall progress bars

### 🖥️ CLI Mode
- Dual mode: `python fractal_gui.py` → GUI; any subcommand → CLI
- Tkinter is **never imported** in CLI mode — zero GUI overhead
- `encrypt`, `decrypt`, `shred`, `analyze` subcommands
- Passwords prompted securely via `getpass` when not provided

---

## Installation

### Option A — Pre-built executable

Download from the [Releases](https://github.com/SiddharthSeng/FractalCrypt/releases/latest)
page (see [Download](#-download) above). No Python required.

### Option B — Run from source

```bash
git clone https://github.com/SiddharthSeng/FractalCrypt.git
cd FractalCrypt
pip install -r requirements.txt
python fractal_gui.py
```

### Option C — Build your own executable

```bash
python fractal_build.py
# Output: dist/FractalCrypt.exe  (Windows)
#         dist/FractalCrypt      (macOS / Linux)
```

---

## Usage

### GUI

```bash
python fractal_gui.py
```

### CLI

```bash
# Encrypt a file
python fractal_gui.py encrypt secret.pdf out.fractal --password MyKey

# Decrypt a file
python fractal_gui.py decrypt out.fractal recovered.pdf --password MyKey

# Encrypt with ASCII armor (email-safe text output)
python fractal_gui.py encrypt photo.jpg out.asc --password MyKey --armor

# Encrypt and shred the original in one step
python fractal_gui.py encrypt report.docx report.fractal --password MyKey --shred-original

# Securely shred files (3-pass DoD)
python fractal_gui.py shred sensitive.pdf private_notes.txt --passes 3

# Shred without confirmation prompt (for scripting)
python fractal_gui.py shred old_data.zip --passes 7 --no-confirm

# Analyze keystream randomness
python fractal_gui.py analyze --password MyKey
python fractal_gui.py analyze --password MyKey --bytes 4096
```

---

## Security Architecture

| Component | Algorithm | Role |
|-----------|-----------|------|
| Keystream | Mandelbrot escape-time + SHA-256 | PRNG byte generation |
| Substitution | Julia orbit-trap S-Box | Non-linear byte scrambling |
| Key derivation | PBKDF2-HMAC-SHA256 (200,000 iters) | Brute-force resistance |
| Randomization | 16-byte `os.urandom()` salt | Unique ciphertext per run |
| Integrity | HMAC-SHA256 | Tamper + wrong-key detection |
| Secure delete | DoD 5220.22-M 3-pass | Forensic elimination |

### Encryption pipeline

```
Password
  │
  └─► PBKDF2-HMAC-SHA256(200k iters, random 16-byte salt)
        │
        ├─► FractalKeyEngine._derive_seed()
        │     ├─► Mandelbrot keystream (SHA-256 diffused)
        │     └─► Julia orbit-trap S-Box (bijective, 256 entries)
        │
        ├─► S-Box substitution (bytes.translate)
        │
        ├─► XOR with Mandelbrot keystream
        │
        └─► HMAC-SHA256 over plaintext → integrity tag
```

### `.fractal` v2 File Format

```
┌──────────────────────────────────────────────────────────────┐
│ [8  bytes]  Magic:  b"FRACTAL1"                              │
│ [16 bytes]  Random salt  (os.urandom(16))                    │
│ [4  bytes]  Original filename length  (big-endian uint32)    │
│ [N  bytes]  Original filename  (UTF-8)                       │
│ [32 bytes]  HMAC-SHA256 of original plaintext                │
│ [4  bytes]  Plaintext length  (big-endian uint32)            │
│ [M  bytes]  Encrypted ciphertext                             │
└──────────────────────────────────────────────────────────────┘
```

---

## Security Considerations

**Honest limitations you should know:**

- **Password strength is the single most important factor.** The cipher is only as
  strong as your password. Use 16+ characters with mixed case, digits, and symbols.
  A weak password exposes the PBKDF2 and everything downstream to dictionary attacks.

- **SSD wear-leveling limits the shredder.** SSDs remap sectors internally, so the
  3-pass DoD shredder may not overwrite every physical location where data was stored.
  Full-disk encryption (BitLocker, FileVault, LUKS) is the most reliable protection
  for SSDs.

- **Novel cipher — not NIST-standardized.** The Mandelbrot keystream + Julia S-Box
  construction has not been formally cryptanalysed to the level of AES-256 or
  ChaCha20. It has not been submitted to NIST or peer-reviewed in academic venues.
  For protecting highly sensitive data (medical, legal, financial), consider layering
  this with AES-256-GCM.

- **No third-party audit.** This is an independent open-source project. It has not
  been audited by a professional security firm.

---

## Contributing

Contributions, bug reports, and feature requests are welcome!

```bash
# Fork and clone
git clone https://github.com/SiddharthSeng/FractalCrypt.git
cd FractalCrypt

# Create a feature branch
git checkout -b feature/your-feature

# Make changes, then commit
git commit -m "feat: description of your change"

# Push and open a Pull Request
git push origin feature/your-feature
```

**Commit message convention:**
- `feat:` — new feature
- `fix:` — bug fix
- `docs:` — documentation change
- `perf:` — performance improvement
- `refactor:` — code change with no functional difference
- `test:` — add or update tests

---

<details>
<summary>📌 Repo setup checklist (maintainer)</summary>

1. **Settings → About** → set description and add topics:  
   `encryption python cryptography tkinter fractal security privacy cli gui file-encryption`
2. **Releases → Draft new release** → tag `v4.0.0`, title `🔮 FractalCrypt v4.0`
3. Upload release assets:
   - `FractalCrypt.exe` (Windows, built on Windows with `python fractal_build.py`)
   - `FractalCrypt-macos` (macOS, built on macOS)
   - `FractalCrypt-linux` (Linux, built on Ubuntu 20.04+)
4. Publish release
5. Add `docs/screenshot.png` (real app screenshot, 1200 × 750 px) and push  
   (see [`docs/placeholder.md`](docs/placeholder.md) for instructions)

</details>

---

## License

MIT © 2025 Siddharth Senguttuvan

See [LICENSE](LICENSE) for the full text.
