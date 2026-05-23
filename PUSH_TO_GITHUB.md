# Pushing FractalCrypt to GitHub

Complete step-by-step guide for first-time publish.

---

## Step 1 — Create the repository on GitHub

1. Open https://github.com/new
2. **Repository name:** `FractalCrypt`
3. **Description:** `Military-grade file encryption powered by fractal mathematics`
4. Visibility: **Public**
5. ⚠ Do **NOT** tick *Add a README*, *Add .gitignore*, or *Choose a license* —  
   the repository must be completely empty so our local push doesn't conflict.
6. Click **Create repository**.

---

## Step 2 — Initialize Git and push all files

Run these commands from the project folder:

```bash
git init
git add .
git commit -m "feat: FractalCrypt v4.0 — fractal file encryption

- Fractal stream cipher (Mandelbrot keystream + Julia S-Box)
- PBKDF2-HMAC-SHA256 key stretching (200,000 iterations)
- Random 16-byte salt per encryption (unique ciphertext every run)
- HMAC-SHA256 integrity verification (tamper + wrong-key detection)
- Multi-file and folder encryption / decryption
- ASCII armor mode (PGP-style .fractal.asc)
- Secure Notes tab (in-memory PBKDF2 note encryption)
- DoD 5220.22-M 3-pass file shredder with 5-minute cooldown
- Key Visualizer (Mandelbrot + Julia fractal renders)
- Keystream randomness analyzer (chi-squared + Shannon entropy)
- CLI + GUI dual mode (tkinter never imported in CLI mode)
- PyInstaller build script for all platforms"

git branch -M main
git remote add origin https://github.com/SiddharthSeng/FractalCrypt.git
git push -u origin main
```

---

## Step 3 — Set repository topics

1. On the repository page, click the gear ⚙️ icon next to **About**.
2. Under **Topics**, add each of the following and press Enter after each:

```
encryption  python  cryptography  tkinter  fractal
security  privacy  gui  cli  file-encryption
```

3. Click **Save changes**.

---

## Step 4 — Build and upload release executables

### 4a. Build the executables (do this on each platform)

```bash
pip install Pillow tkinterdnd2 pyinstaller
python fractal_build.py --clean
```

Output files:
| Platform | Output |
|----------|--------|
| Windows  | `dist/FractalCrypt.exe` |
| macOS    | `dist/FractalCrypt` (or `dist/FractalCrypt.app`) |
| Linux    | `dist/FractalCrypt` |

### 4b. Create the GitHub release

1. Go to your repository → **Releases** → **Draft a new release**.
2. Click **Choose a tag** → type `v4.0.0` → click **Create new tag: v4.0.0**.
3. **Release title:** `🔮 FractalCrypt v4.0`
4. **Description:**

```markdown
## 🔮 FractalCrypt v4.0

First public release of FractalCrypt — file encryption powered by fractal mathematics.

### What's included

- 5-tab desktop GUI (Encrypt/Decrypt, Key Visualizer, Analysis, Secure Notes, Shredder)
- CLI mode for scripting and automation
- PBKDF2-HMAC-SHA256 key stretching (200,000 iterations)
- Random salt per encryption — unique ciphertext every run
- DoD 5220.22-M 3-pass secure file shredder with 5-minute cooldown
- ASCII armor mode for email-safe sharing
- PyInstaller build script for Windows, macOS, and Linux

### Installation (from source)

```bash
pip install Pillow tkinterdnd2
python fractal_gui.py
```

### Download

See **Assets** below for pre-built executables.
Build from source using `python fractal_build.py` for your platform.
```

5. Under **Assets**, click **Attach binaries** and upload:
   - `FractalCrypt.exe` (Windows)
   - `FractalCrypt` (macOS binary — rename to `FractalCrypt-macos`)
   - `FractalCrypt` (Linux binary — rename to `FractalCrypt-linux`)
6. Click **Publish release**.

---

## Step 5 — Add the app screenshot

1. Launch the app and take a 1200 × 750 px screenshot.
   See `docs/placeholder.md` for detailed instructions.
2. Save as `docs/screenshot.png`.
3. Push:

```bash
git add docs/screenshot.png
git commit -m "docs: add app screenshot"
git push
```

The README banner image will automatically render on GitHub.

---

## Step 6 — Verify

After pushing, check:

- [ ] Repository visible at https://github.com/SiddharthSeng/FractalCrypt
- [ ] All source files are present
- [ ] README renders correctly (no broken image/badge links)
- [ ] Topics are set
- [ ] Release v4.0.0 is published with assets
- [ ] `docs/screenshot.png` is visible in the README

---

## Quick reference — common Git commands

```bash
# Check status
git status

# Add a single file
git add path/to/file

# Amend last commit message (before push)
git commit --amend -m "new message"

# Force push after amend (only safe if you haven't shared yet)
git push --force-with-lease

# Pull latest changes
git pull origin main
```
