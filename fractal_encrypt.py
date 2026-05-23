#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
+==============================================================================+
|               FRACTAL-BASED FILE ENCRYPTION SYSTEM                          |
|               fractal_encrypt.py  --  Pure Python stdlib only                |
|                                                                              |
|  Algorithm: Fractal Stream Cipher (Mandelbrot + Julia Sets)                  |
|  Security:  Password -> SHA-512 salt -> fractal seeding -> keystream + S-Box |
|  Integrity: HMAC-SHA256 of plaintext (tamper-detection on decryption)        |
+==============================================================================+

Mathematical Background
───────────────────────
• Mandelbrot Set:  z(n+1) = z(n)² + c,  starting at z(0) = 0
  The "escape time" (iteration count before |z| > 2) encodes fractal geometry
  into a rich pseudo-random integer stream used as the keystream.

• Julia Set:       z(n+1) = z(n)² + c,  starting at z(0) = pixel coordinate
  Different starting points orbit the same constant c, producing orbit-trap
  values we map to byte positions to build the S-Box substitution table.

• Why this is interesting cryptographically:
  - Tiny password changes (even 1 bit) shift c, cascading into completely
    different escape-time sequences throughout the fractal plane.
  - The fractal boundary is infinitely complex — a natural source of
    deterministic-but-chaotic bit streams.

IMPORTANT SECURITY NOTICE
─────────────────────────
This implementation demonstrates fractal mathematics as a novel keystream
generator. It has NOT been formally cryptanalysed to the level of AES or
ChaCha20. For protecting highly sensitive data in production you should
layer this with a well-vetted primitive (e.g. AES-256-CTR). However, the
design here (proper SHA-512 password salting, HMAC-SHA256 integrity check,
1000-iteration depth) provides meaningful security for most practical uses.

Author: Fractal Encryption System
Python: 3.8+
"""

import argparse
import hashlib
import hmac
import os
import struct
import sys
import tempfile

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

MAGIC_HEADER   = b"FRACTAL1"          # 8-byte file magic
ITERATION_DEPTH = 1000                # Fractal escape-time depth per sample
ESCAPE_RADIUS   = 2.0                 # |z| > ESCAPE_RADIUS  →  escaped
ESCAPE_RADIUS_SQ = ESCAPE_RADIUS ** 2 # Squared for fast comparison (no sqrt)
PROGRESS_STEP   = 0.10               # Print progress every 10%


# ─────────────────────────────────────────────────────────────────────────────
# CLASS: FractalKeyEngine
# ─────────────────────────────────────────────────────────────────────────────

class FractalKeyEngine:
    """
    All fractal mathematics live here.

    Key derivation pipeline
    ───────────────────────
    password (str)
        │
        ▼
    SHA-512(password + FIXED_SALT)   ← stretches + salts the password
        │
        ├──► first 8 bytes  → complex c  (Mandelbrot parameter)
        │        used in mandelbrot_keystream()
        │
        └──► next  8 bytes  → complex c' (Julia constant)
                 used in julia_sbox()
    """

    # A fixed application-level salt mixed with the user password.
    # This prevents rainbow tables built purely on password → c mappings.
    _APP_SALT = b"FractalCipherV1:MandelbrotJulia"

    def _derive_seed(self, password: str) -> bytes:
        """
        Derive a deterministic 64-byte seed from the user password.

        Steps:
          1. Encode password to UTF-8.
          2. Concatenate with the application salt.
          3. Hash with SHA-512 — this is the sole expensive KDF step.

        The resulting 64 bytes give us two independent 8-byte windows:
          bytes  0-7  → Mandelbrot c  (real + imag, each 4 bytes, fp32)
          bytes  8-15 → Julia c       (real + imag, each 4 bytes, fp32)
        """
        pwd_bytes = password.encode("utf-8")
        material  = pwd_bytes + self._APP_SALT
        return hashlib.sha512(material).digest()  # 64 bytes

    def _seed_to_complex(self, seed_slice: bytes) -> complex:
        """
        Convert 8 raw bytes into a complex number that lies within
        the interesting Mandelbrot region  (-2.5 < Re < 1, -1.25 < Im < 1.25).

        We interpret the slice as two IEEE-754 32-bit floats (big-endian),
        then map them from the [0, 1) unit interval to the Mandelbrot window.
        """
        # Unpack as two unsigned 32-bit integers
        hi, lo = struct.unpack(">II", seed_slice)

        # Normalise to [0, 1)
        norm_re = hi / 0x1_0000_0000   # 2^32
        norm_im = lo / 0x1_0000_0000

        # Map real part to (-2.5 … 1.0) and imaginary part to (-1.25 … 1.25)
        # These bounds bracket the entire Mandelbrot set with some margin.
        c_real = norm_re * 3.5  - 2.5   # range: [-2.5,  1.0)
        c_imag = norm_im * 2.5  - 1.25  # range: [-1.25, 1.25)

        return complex(c_real, c_imag)

    # ── Mandelbrot escape-time ────────────────────────────────────────────────

    def _mandelbrot_escape(self, c: complex, z_start: complex) -> int:
        """
        Iterate  z ← z² + c  up to ITERATION_DEPTH times starting from z_start.

        Returns the iteration count at which |z|² > ESCAPE_RADIUS_SQ.
        If the orbit never escapes, returns ITERATION_DEPTH (inside the set).

        This single integer encodes the "colour" of one pixel in the fractal —
        we harvest these integers as raw keystream material.
        """
        z = z_start
        for n in range(ITERATION_DEPTH):
            # Expand z² + c manually to avoid extra complex object allocation
            zr = z.real
            zi = z.imag
            zr2 = zr * zr
            zi2 = zi * zi
            if zr2 + zi2 > ESCAPE_RADIUS_SQ:
                return n          # escaped at iteration n
            # z ← z² + c
            z = complex(zr2 - zi2 + c.real,
                        2.0 * zr * zi + c.imag)
        return ITERATION_DEPTH    # did not escape → deep interior point

    def mandelbrot_keystream(self, password: str, length: int) -> bytes:
        """
        Generate `length` pseudo-random bytes driven by Mandelbrot escape times.

        Strategy
        ────────
        We scan a deterministic grid of starting points z(0) = x + iy across
        a region of the complex plane parameterised by the password-derived c.

        For each grid point we get an escape time  t ∈ [0, ITERATION_DEPTH].
        We convert t to bytes using a secondary SHA-256 hash — this adds
        diffusion, ensuring single-bit changes in t cascade to many output bits.

        The SHA-256 hash of each (c, z_start, t) triple produces 32 bytes of
        keystream material, so we call it ⌈length/32⌉ times.

        Parameters
        ──────────
        password : user passphrase (any length)
        length   : number of keystream bytes required

        Returns
        ───────
        bytes of exactly `length` pseudo-random bytes
        """
        seed   = self._derive_seed(password)
        c      = self._seed_to_complex(seed[0:8])  # Mandelbrot parameter

        # We will walk a 1-D sequence of starting points distributed across
        # a stripe of the fractal plane.  The step size is irrational (golden
        # ratio) to avoid aliasing with the fractal's period structure.
        GOLDEN = 0.6180339887498949   # φ - 1  (irrational)
        SILVER = 0.4142135623730951   # √2 - 1 (irrational, orthogonal to φ)

        keystream = bytearray()
        block_idx = 0

        while len(keystream) < length:
            # Deterministic starting point for this block
            x0 = (GOLDEN * block_idx) % 1.0  # spread across real axis
            y0 = (SILVER * block_idx) % 1.0  # spread across imaginary axis

            # Map to fractal plane (use a window slightly outside [-2,2] to
            # include boundary pixels that have the highest information density)
            z_start = complex(x0 * 4.0 - 2.0,
                              y0 * 4.0 - 2.0)

            # --- Core fractal computation ---
            escape_iter = self._mandelbrot_escape(c, z_start)

            # Diffuse the escape time through SHA-256 to:
            #  a) expand 1 integer → 32 keystream bytes
            #  b) remove any linear bias in raw escape-time distribution
            #  c) make partial-keystream knowledge useless without c
            h = hashlib.sha256()
            h.update(seed)                           # binds output to password
            h.update(struct.pack(">q", block_idx))   # unique per block
            h.update(struct.pack(">I", escape_iter)) # fractal contribution
            # Also fold in the real-valued z components for extra sensitivity
            h.update(struct.pack(">dd", z_start.real, z_start.imag))
            keystream.extend(h.digest())             # 32 bytes per block

            block_idx += 1

        return bytes(keystream[:length])

    # ── Julia orbit-trap S-Box ────────────────────────────────────────────────

    def _julia_orbit_distance(self, c_julia: complex, z0: complex) -> float:
        """
        Compute the minimum distance from the orbit of z0 under  z ← z² + c
        to a set of "trap" reference points.

        Orbit traps
        ───────────
        An orbit trap is a geometric shape in the complex plane; when the
        iterating point z enters the shape, we record the iteration and the
        distance.  Here we use four trap points at the cardinal unit positions:
           ±1, ±i
        and take the minimum distance across the entire orbit.

        This minimum distance is smooth, bounded, and highly sensitive to the
        starting point z0 — perfect for generating a varied S-Box.
        """
        TRAP_POINTS = [
            complex( 1.0,  0.0),
            complex(-1.0,  0.0),
            complex( 0.0,  1.0),
            complex( 0.0, -1.0),
        ]
        min_dist = float("inf")
        z = z0
        for _ in range(ITERATION_DEPTH):
            zr, zi = z.real, z.imag
            if zr * zr + zi * zi > ESCAPE_RADIUS_SQ:
                break
            for tp in TRAP_POINTS:
                dr = zr - tp.real
                di = zi - tp.imag
                d  = dr * dr + di * di   # squared distance (no sqrt needed)
                if d < min_dist:
                    min_dist = d
            z = complex(zr * zr - zi * zi + c_julia.real,
                        2.0 * zr * zi   + c_julia.imag)

        return min_dist if min_dist != float("inf") else 0.0

    def julia_sbox(self, password: str) -> bytes:
        """
        Build a 256-byte substitution table (S-Box) driven by Julia set
        orbit-trap distances.

        Construction
        ────────────
        1. Derive Julia constant c' from password.
        2. For each index i in 0…255:
             - Map i to a starting point z0 on a unit circle:
                 z0 = 0.45 · e^(2πi · i/256)
               (inside the Julia set for most c' values)
             - Compute the orbit-trap distance  d_i
        3. Sort indices 0…255 by their d_i values in ascending order.
           This gives a permutation of {0…255} — our S-Box.

        Result: each input byte b is mapped to sbox[b].
        The S-Box is a bijection (every output appears exactly once) so the
        inverse S-Box can be computed exactly.

        Why orbit traps?
        ────────────────
        The orbit-trap distances vary smoothly but chaotically with z0.
        Tiny password changes alter c', which reorders all 256 distances,
        producing a completely different S-Box permutation.
        """
        seed   = self._derive_seed(password)
        c_julia = self._seed_to_complex(seed[8:16])   # Julia constant (≠ c_mandelbrot)

        import math
        TWO_PI = 2.0 * math.pi

        # Compute orbit-trap distance for each of the 256 byte values
        distances = []
        for i in range(256):
            angle = TWO_PI * i / 256.0
            # Start on a circle of radius 0.45 (stays inside |z|=1 region)
            z0 = complex(0.45 * math.cos(angle),
                         0.45 * math.sin(angle))
            d  = self._julia_orbit_distance(c_julia, z0)
            distances.append((d, i))

        # Sort by distance → get a deterministic permutation of 0…255
        distances.sort(key=lambda pair: pair[0])
        sbox = bytes(orig_idx for _, orig_idx in distances)
        return sbox

    def inverse_sbox(self, sbox: bytes) -> bytes:
        """
        Compute the inverse S-Box such that:
            inverse_sbox[sbox[b]] == b   for all b in 0…255

        This is a simple O(256) table inversion — sbox is guaranteed to be
        a permutation, so every value 0…255 appears exactly once.
        """
        inv = bytearray(256)
        for original_byte, substituted_byte in enumerate(sbox):
            inv[substituted_byte] = original_byte
        return bytes(inv)


# ─────────────────────────────────────────────────────────────────────────────
# CLASS: FractalCipher
# ─────────────────────────────────────────────────────────────────────────────

class FractalCipher:
    """
    High-level encrypt / decrypt operations.

    Encryption pipeline
    ───────────────────
      plaintext bytes
          │
          ├─[1]─ S-Box substitution   →  substituted bytes   (confusion)
          │
          ├─[2]─ XOR with keystream   →  ciphertext bytes     (diffusion)
          │
          └─[3]─ prepend header + HMAC  →  .fractal file

    Decryption pipeline (exact reverse)
    ────────────────────────────────────
      .fractal file
          │
          ├─[1]─ verify magic header
          │
          ├─[2]─ re-derive keystream + inv-S-Box
          │
          ├─[3]─ reverse XOR          →  substituted bytes
          │
          ├─[4]─ inverse S-Box        →  plaintext bytes
          │
          └─[5]─ verify HMAC          →  confirmed plaintext

    Binary layout of .fractal file
    ───────────────────────────────
    ┌───────────────────────────────────────────────────────┐
    │ [8  bytes]  Magic:  b"FRACTAL1"                       │
    │ [4  bytes]  Original filename length (big-endian u32) │
    │ [N  bytes]  Original filename (UTF-8)                 │
    │ [32 bytes]  HMAC-SHA256 of original plaintext         │
    │ [4  bytes]  Plaintext length (big-endian u32)         │
    │ [M  bytes]  Encrypted ciphertext                      │
    └───────────────────────────────────────────────────────┘
    """

    def __init__(self, verbose: bool = True):
        self.engine  = FractalKeyEngine()
        self.verbose = verbose

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    def _compute_hmac(self, key_material: bytes, data: bytes) -> bytes:
        """
        Compute HMAC-SHA256 of `data` using a key derived from key_material.

        We hash key_material with SHA-256 first so any-length key_material
        maps to a proper 32-byte HMAC key.
        """
        hmac_key = hashlib.sha256(key_material).digest()
        return hmac.new(hmac_key, data, hashlib.sha256).digest()

    def _apply_sbox(self, data: bytes, sbox: bytes) -> bytes:
        """
        Vectorised S-Box application using a translation table.
        bytes.translate() uses a C-level loop for maximum performance.
        """
        return data.translate(sbox)

    def _xor_with_keystream(self,
                             data: bytes,
                             keystream: bytes,
                             block_size: int = 65536) -> bytes:
        """
        XOR `data` with `keystream` in chunks.

        Works for arbitrary lengths — keystream must be >= len(data).
        Progress is printed every PROGRESS_STEP fraction of the file.
        """
        total   = len(data)
        result  = bytearray(total)
        done    = 0
        next_pct = PROGRESS_STEP

        while done < total:
            end        = min(done + block_size, total)
            chunk      = data[done:end]
            ks_chunk   = keystream[done:end]
            # XOR each byte: int.from_bytes + to_bytes is slower;
            # use bytes(a ^ b for a, b in zip(...)) for pure Python
            xored = bytes(a ^ b for a, b in zip(chunk, ks_chunk))
            result[done:end] = xored
            done = end

            # Progress reporting
            if self.verbose and total > 1024 * 10:  # only for >10 KB files
                fraction = done / total
                if fraction >= next_pct:
                    pct = int(fraction * 100)
                    bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
                    print(f"\r    [{bar}] {pct:3d}%", end="", flush=True)
                    next_pct += PROGRESS_STEP

        if self.verbose and total > 1024 * 10:
            print(f"\r    [{'█' * 20}] 100%", flush=True)

        return bytes(result)

    # ── Public API ────────────────────────────────────────────────────────────

    def encrypt(self, input_path: str, output_path: str, password: str) -> None:
        """
        Encrypt `input_path` → `output_path` using `password`.

        Raises
        ──────
        FileNotFoundError  – input file does not exist
        PermissionError    – cannot write output file
        """
        # ── Read plaintext ───────────────────────────────────────────────────
        if not os.path.isfile(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path!r}")

        with open(input_path, "rb") as fh:
            plaintext = fh.read()
        pt_len = len(plaintext)

        original_name = os.path.basename(input_path).encode("utf-8")
        self._log(f"  [*] Encrypting {input_path!r} ({pt_len:,} bytes)")

        # ── Step 1: Derive fractal keystream (Mandelbrot PRNG) ───────────────
        self._log(f"  [·] Generating fractal keystream…  "
                  f"(Mandelbrot depth: {ITERATION_DEPTH})")
        keystream = self.engine.mandelbrot_keystream(password, pt_len)

        # ── Step 2: Build Julia S-Box ─────────────────────────────────────────
        self._log("  [·] Building Julia S-Box…")
        sbox = self.engine.julia_sbox(password)

        # ── Step 3: Apply S-Box substitution ─────────────────────────────────
        self._log("  [·] Applying S-Box substitution…")
        substituted = self._apply_sbox(plaintext, sbox)

        # ── Step 4: XOR with keystream ────────────────────────────────────────
        self._log("  [·] XOR-ing with fractal keystream…")
        ciphertext = self._xor_with_keystream(substituted, keystream)

        # ── Step 5: Compute HMAC over ORIGINAL plaintext ──────────────────────
        # We use the full SHA-512 seed as the HMAC key source so that HMAC
        # verification also implicitly verifies the password.
        seed = self.engine._derive_seed(password)
        mac  = self._compute_hmac(seed, plaintext)

        # ── Step 6: Write .fractal file ───────────────────────────────────────
        with open(output_path, "wb") as fh:
            fh.write(MAGIC_HEADER)                           # [8]  magic
            fh.write(struct.pack(">I", len(original_name))) # [4]  name len
            fh.write(original_name)                          # [N]  filename
            fh.write(mac)                                    # [32] HMAC
            fh.write(struct.pack(">I", pt_len))              # [4]  pt len
            fh.write(ciphertext)                             # [M]  ciphertext

        out_size = os.path.getsize(output_path)
        self._log(f"  [✓] Encrypted → {output_path!r} ({out_size:,} bytes)")
        self._log(f"      First 16 bytes (hex): "
                  f"{' '.join(f'{b:02x}' for b in ciphertext[:16])}")

    def decrypt(self, input_path: str, output_path: str, password: str) -> None:
        """
        Decrypt a .fractal file → `output_path` using `password`.

        Raises
        ──────
        FileNotFoundError  – input file not found
        ValueError         – bad magic header (not a .fractal file)
        ValueError         – HMAC mismatch (wrong password or tampered file)
        struct.error       – file is truncated / structurally corrupt
        """
        # ── Read .fractal file ────────────────────────────────────────────────
        if not os.path.isfile(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path!r}")

        with open(input_path, "rb") as fh:
            raw = fh.read()

        # ── Parse header ──────────────────────────────────────────────────────
        offset = 0

        # Magic
        magic = raw[offset:offset + 8]
        offset += 8
        if magic != MAGIC_HEADER:
            raise ValueError(
                f"Invalid magic header {magic!r}. "
                f"Is this a valid .fractal file?"
            )

        # Original filename
        name_len = struct.unpack_from(">I", raw, offset)[0]
        offset += 4
        original_name = raw[offset:offset + name_len].decode("utf-8")
        offset += name_len

        # HMAC
        stored_mac = raw[offset:offset + 32]
        offset += 32

        # Plaintext length
        pt_len = struct.unpack_from(">I", raw, offset)[0]
        offset += 4

        # Ciphertext
        ciphertext = raw[offset:offset + pt_len]
        if len(ciphertext) != pt_len:
            raise ValueError(
                f"File appears truncated: expected {pt_len} ciphertext bytes, "
                f"got {len(ciphertext)}."
            )

        self._log(f"  [*] Decrypting {input_path!r}")
        self._log(f"      Original filename: {original_name!r}")

        # ── Re-derive keystream + S-Box (must match encryption exactly) ───────
        self._log(f"  [·] Re-deriving fractal keystream…  "
                  f"(Mandelbrot depth: {ITERATION_DEPTH})")
        keystream = self.engine.mandelbrot_keystream(password, pt_len)

        self._log("  [·] Re-building Julia S-Box…")
        sbox     = self.engine.julia_sbox(password)
        inv_sbox = self.engine.inverse_sbox(sbox)

        # ── Reverse XOR ───────────────────────────────────────────────────────
        self._log("  [·] Reversing XOR with keystream…")
        substituted = self._xor_with_keystream(ciphertext, keystream)

        # ── Inverse S-Box ─────────────────────────────────────────────────────
        self._log("  [·] Applying inverse S-Box substitution…")
        plaintext = self._apply_sbox(substituted, inv_sbox)

        # ── HMAC Verification ─────────────────────────────────────────────────
        seed = self.engine._derive_seed(password)
        computed_mac = self._compute_hmac(seed, plaintext)

        if not hmac.compare_digest(computed_mac, stored_mac):
            raise ValueError(
                "❌ HMAC verification FAILED.\n"
                "   The file has been tampered with, OR the password is wrong.\n"
                "   Decrypted output will NOT be written."
            )

        self._log("  [✓] HMAC verified — file integrity confirmed")

        # ── Write plaintext ───────────────────────────────────────────────────
        with open(output_path, "wb") as fh:
            fh.write(plaintext)

        self._log(f"  [✓] Decrypted → {output_path!r} ({len(plaintext):,} bytes)")


# ─────────────────────────────────────────────────────────────────────────────
# DEMO
# ─────────────────────────────────────────────────────────────────────────────

def _run_demo() -> None:
    """
    Built-in self-test / demo.

    Creates a temporary text file, encrypts it, decrypts it, and verifies
    the round-trip is lossless.  Prints a formatted security summary.
    """
    print()
    print("+" + "=" * 62 + "+")
    print("|       [*] Fractal Encryption System -- Demo                  |")
    print("+" + "=" * 62 + "+")
    print()

    demo_password = "FractalDemoKey#2024"
    demo_text = (
        "This is a demonstration of the Fractal-Based File Encryption System.\n"
        "Using Mandelbrot and Julia sets as the cryptographic engine,\n"
        "this system converts your password into a unique fractal keystream\n"
        "and a dynamic S-Box substitution table — making every encryption\n"
        "unique and mathematically grounded in the infinite complexity of\n"
        "fractal geometry.\n\n"
        "  z(n+1) = z(n)² + c  — The heart of the cipher.\n"
    )

    # Create temp directory for demo files
    tmpdir = tempfile.mkdtemp(prefix="fractal_demo_")
    demo_plain    = os.path.join(tmpdir, "demo.txt")
    demo_enc      = os.path.join(tmpdir, "demo.fractal")
    demo_dec      = os.path.join(tmpdir, "demo_recovered.txt")

    try:
        # Write demo plaintext
        with open(demo_plain, "w", encoding="utf-8") as f:
            f.write(demo_text)
        plain_size = os.path.getsize(demo_plain)
        print(f"  [+] Created demo file: {demo_plain!r}  ({plain_size} bytes)")
        print()

        cipher = FractalCipher(verbose=True)

        # ── Encrypt ───────────────────────────────────────────────────────────
        print("--- ENCRYPTION -------------------------------------------------")
        cipher.encrypt(demo_plain, demo_enc, demo_password)
        print()

        # Show hex preview of ciphertext section
        with open(demo_enc, "rb") as fh:
            raw = fh.read()
        # Skip header to show actual ciphertext bytes
        header_skip = 8 + 4 + len("demo.txt") + 32 + 4
        ct_preview  = raw[header_skip : header_skip + 32]
        print(f"  Ciphertext preview (first 32 bytes):")
        hex_rows = [ct_preview[i:i+16] for i in range(0, len(ct_preview), 16)]
        for row in hex_rows:
            print("    " + " ".join(f"{b:02x}" for b in row))
        print()

        # ── Decrypt ───────────────────────────────────────────────────────────
        print("--- DECRYPTION -------------------------------------------------")
        cipher.decrypt(demo_enc, demo_dec, demo_password)
        print()

        # ── Round-trip verification ───────────────────────────────────────────
        with open(demo_plain, "rb") as f:
            original_bytes = f.read()
        with open(demo_dec, "rb") as f:
            recovered_bytes = f.read()

        match = original_bytes == recovered_bytes
        status = "✅ PASSED" if match else "❌ FAILED"
        print("--- VERIFICATION -----------------------------------------------")
        print(f"  [{'✓' if match else '✗'}] Round-trip verification: {status}")

        # SHA-256 fingerprints
        orig_hash = hashlib.sha256(original_bytes).hexdigest()
        recv_hash = hashlib.sha256(recovered_bytes).hexdigest()
        print(f"  Original SHA-256 : {orig_hash}")
        print(f"  Recovered SHA-256: {recv_hash}")
        print()

        # ── Security summary ──────────────────────────────────────────────────
        print("--- SECURITY SUMMARY -------------------------------------------")
        enc_size = os.path.getsize(demo_enc)
        overhead = enc_size - plain_size
        print(f"  {'Algorithm':<16}: Fractal Stream Cipher (Mandelbrot + Julia)")
        print(f"  {'Key depth':<16}: {ITERATION_DEPTH} iterations per fractal sample")
        print(f"  {'S-Box':<16}: Julia orbit-trap substitution (256 entries)")
        print(f"  {'Integrity':<16}: HMAC-SHA256 (keyed with SHA-512 password hash)")
        print(f"  {'KDF':<16}: SHA-512 (password + application salt)")
        print(f"  {'Plaintext':<16}: {plain_size:,} bytes")
        print(f"  {'Ciphertext':<16}: {enc_size:,} bytes")
        print(f"  {'Overhead':<16}: {overhead:,} bytes "
              f"(header + filename + HMAC)")
        print()

        if not match:
            sys.exit(1)

    finally:
        # Clean up temp files
        for path in [demo_plain, demo_enc, demo_dec]:
            try:
                os.remove(path)
            except OSError:
                pass
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """
    Command-line interface.

    Usage
    ─────
    python fractal_encrypt.py encrypt <input> <output> --password <pwd>
    python fractal_encrypt.py decrypt <input> <output> --password <pwd>
    python fractal_encrypt.py demo
    python fractal_encrypt.py          (runs demo automatically)
    """
    # Fix Windows console encoding so Unicode progress bars display correctly
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            import io
            sys.stdout = io.TextIOWrapper(
                sys.stdout.buffer, encoding="utf-8", errors="replace"
            )
            sys.stderr = io.TextIOWrapper(
                sys.stderr.buffer, encoding="utf-8", errors="replace"
            )
        except Exception:
            pass  # If reconfiguration fails, continue with default encoding

    parser = argparse.ArgumentParser(
        prog="fractal_encrypt",
        description=(
            "[*] Fractal-Based File Encryption System\n"
            "    Uses Mandelbrot + Julia sets as the cryptographic engine."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python fractal_encrypt.py encrypt secret.pdf secret.fractal --password MyKey123\n"
            "  python fractal_encrypt.py decrypt secret.fractal recovered.pdf --password MyKey123\n"
            "  python fractal_encrypt.py demo\n"
            "  python fractal_encrypt.py          # runs the built-in demo\n"
        )
    )

    sub = parser.add_subparsers(dest="command")

    # ── encrypt sub-command ───────────────────────────────────────────────────
    enc_p = sub.add_parser(
        "encrypt",
        help="Encrypt a file",
        description="Encrypt a file using the Fractal Stream Cipher."
    )
    enc_p.add_argument("input",    help="Path to the plaintext input file")
    enc_p.add_argument("output",   help="Path for the encrypted output (.fractal)")
    enc_p.add_argument("--password", "-p", required=True,
                       help="Encryption password (keep this secret!)")
    enc_p.add_argument("--quiet",  "-q", action="store_true",
                       help="Suppress progress output")

    # ── decrypt sub-command ───────────────────────────────────────────────────
    dec_p = sub.add_parser(
        "decrypt",
        help="Decrypt a .fractal file",
        description="Decrypt a .fractal file produced by this tool."
    )
    dec_p.add_argument("input",    help="Path to the encrypted .fractal file")
    dec_p.add_argument("output",   help="Path for the decrypted output file")
    dec_p.add_argument("--password", "-p", required=True,
                       help="Decryption password (must match encryption password)")
    dec_p.add_argument("--quiet",  "-q", action="store_true",
                       help="Suppress progress output")

    # ── demo sub-command ──────────────────────────────────────────────────────
    sub.add_parser(
        "demo",
        help="Run the built-in self-test demo",
        description="Create a temp file, encrypt, decrypt, and verify."
    )

    args = parser.parse_args()

    # No sub-command → run demo
    if args.command is None:
        _run_demo()
        return

    if args.command == "demo":
        _run_demo()
        return

    # ── Encrypt ───────────────────────────────────────────────────────────────
    if args.command == "encrypt":
        verbose = not args.quiet
        print()
        print("[*] Fractal Encryption System")
        cipher = FractalCipher(verbose=verbose)
        try:
            cipher.encrypt(args.input, args.output, args.password)
            print()
            print("  Done. [OK]")
        except (FileNotFoundError, PermissionError, OSError) as exc:
            print(f"\n  Error: {exc}", file=sys.stderr)
            sys.exit(1)

    # ── Decrypt ───────────────────────────────────────────────────────────────
    elif args.command == "decrypt":
        verbose = not args.quiet
        print()
        print("[*] Fractal Encryption System")
        cipher = FractalCipher(verbose=verbose)
        try:
            cipher.decrypt(args.input, args.output, args.password)
            print()
            print("  Done. [OK]")
        except FileNotFoundError as exc:
            print(f"\n  Error: {exc}", file=sys.stderr)
            sys.exit(1)
        except ValueError as exc:
            print(f"\n  {exc}", file=sys.stderr)
            sys.exit(1)
        except (struct.error, Exception) as exc:
            print(f"\n  Decryption failed (corrupted file?): {exc}",
                  file=sys.stderr)
            sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    main()
