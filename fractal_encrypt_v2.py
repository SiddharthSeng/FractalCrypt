#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
+==============================================================================+
|           FRACTAL-BASED FILE ENCRYPTION SYSTEM  —  VERSION 2                |
|           fractal_encrypt_v2.py  --  Pure Python stdlib only                 |
|                                                                              |
|  Security upgrades over v1:                                                  |
|    • PBKDF2-HMAC-SHA256 key stretching (200,000 iterations)                 |
|    • Per-encryption 16-byte random salt (every run is unique)               |
|    • New binary header layout (v2 format)                                    |
|                                                                              |
|  V2 Binary Layout                                                            |
|  ────────────────                                                            |
|  [8  bytes]  Magic:  b"FRACTAL1"                                            |
|  [16 bytes]  Random salt  (os.urandom(16))                                  |
|  [4  bytes]  Original filename length  (big-endian uint32)                  |
|  [N  bytes]  Original filename  (UTF-8)                                     |
|  [32 bytes]  HMAC-SHA256 of original plaintext                              |
|  [4  bytes]  Plaintext length  (big-endian uint32)                          |
|  [M  bytes]  Encrypted ciphertext                                           |
|                                                                              |
|  All original FractalKeyEngine and FractalCipher classes are preserved       |
|  so existing .fractal (v1) files can still be decrypted via FractalCipher.  |
+==============================================================================+
"""

import hashlib
import hmac
import os
import struct

# Re-export everything from the original module so importers only need v2
from fractal_encrypt import (
    FractalKeyEngine,
    FractalCipher,
    MAGIC_HEADER,
    ITERATION_DEPTH,
    ESCAPE_RADIUS,
    ESCAPE_RADIUS_SQ,
)

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS (v2)
# ─────────────────────────────────────────────────────────────────────────────

PBKDF2_ITERATIONS = 200_000   # Work factor — makes brute-force ~200k× slower
SALT_BYTES        = 16        # Random salt length in bytes


# ─────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def stretch_password(password: str, salt: bytes) -> bytes:
    """
    Stretch a user password using PBKDF2-HMAC-SHA256.

    Parameters
    ----------
    password : str
        The raw user passphrase.
    salt : bytes
        A 16-byte random salt (unique per encryption).

    Returns
    -------
    bytes
        32-byte derived key suitable for use with FractalKeyEngine.
        We encode this as a hex string so FractalKeyEngine._derive_seed()
        can consume it as a "password" with full byte entropy.

    Security Note
    -------------
    200,000 PBKDF2 iterations means an attacker must perform 200,000 SHA-256
    evaluations per password guess, making dictionary attacks ~200,000× slower
    compared to a plain SHA-512 derivation.
    """
    raw = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    # Return as hex string — FractalKeyEngine treats it as a "password"
    # so its internal SHA-512 KDF adds another mixing layer on top.
    return raw.hex()


# ─────────────────────────────────────────────────────────────────────────────
# CLASS: FractalCipherV2
# ─────────────────────────────────────────────────────────────────────────────

class FractalCipherV2:
    """
    Security-hardened fractal cipher with PBKDF2 key stretching and random salt.

    This class provides the same encrypt/decrypt interface as FractalCipher but
    uses the new v2 binary format, which embeds a random 16-byte salt in the
    file header.  Every encryption call generates a fresh salt, ensuring that:

      • Same password + same file → completely different ciphertext every time.
      • Brute-force attacks require 200,000 SHA-256 evaluations per guess.

    V1 files (.fractal produced by FractalCipher) remain readable via the
    original FractalCipher class.  This class only produces v2 files.

    Attributes
    ----------
    engine : FractalKeyEngine
        Shared fractal mathematics engine.
    verbose : bool
        If True, progress messages are emitted to stdout.
    """

    def __init__(self, verbose: bool = False) -> None:
        """
        Initialise the cipher with a shared FractalKeyEngine.

        Parameters
        ----------
        verbose : bool
            Enable stdout progress logging.
        """
        self.engine  = FractalKeyEngine()
        self.verbose = verbose

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        """Print a progress message if verbose mode is active."""
        if self.verbose:
            print(msg)

    def _compute_hmac(self, key_material: bytes, data: bytes) -> bytes:
        """
        Compute HMAC-SHA256 over `data` keyed by `key_material`.

        We pre-hash key_material to normalise its length to exactly 32 bytes
        before using it as the HMAC key.

        Parameters
        ----------
        key_material : bytes
            Raw key bytes (any length).
        data : bytes
            Data to authenticate.

        Returns
        -------
        bytes
            32-byte HMAC-SHA256 digest.
        """
        hmac_key = hashlib.sha256(key_material).digest()
        return hmac.new(hmac_key, data, hashlib.sha256).digest()

    def _apply_sbox(self, data: bytes, sbox: bytes) -> bytes:
        """
        Apply an S-Box substitution to `data` using the fast C-level
        bytes.translate() method.

        Parameters
        ----------
        data : bytes
            Input bytes to substitute.
        sbox : bytes
            256-byte permutation table.

        Returns
        -------
        bytes
            Substituted output (same length as input).
        """
        return data.translate(sbox)

    def _xor_with_keystream(
        self,
        data: bytes,
        keystream: bytes,
        progress_cb=None,
    ) -> bytes:
        """
        XOR `data` byte-by-byte with `keystream`.

        Processes data in 64 KiB chunks for memory efficiency and calls
        `progress_cb(fraction)` periodically when provided.

        Parameters
        ----------
        data : bytes
            Input plaintext or ciphertext.
        keystream : bytes
            Pre-generated keystream (must be >= len(data)).
        progress_cb : callable or None
            Optional callback receiving a float in [0.0, 1.0] as progress.

        Returns
        -------
        bytes
            XOR result of same length as `data`.
        """
        BLOCK = 65536
        total  = len(data)
        result = bytearray(total)
        done   = 0

        while done < total:
            end      = min(done + BLOCK, total)
            chunk    = data[done:end]
            ks_chunk = keystream[done:end]
            result[done:end] = bytes(a ^ b for a, b in zip(chunk, ks_chunk))
            done = end
            if progress_cb and total > 0:
                progress_cb(done / total)

        return bytes(result)

    # ── Public API ────────────────────────────────────────────────────────────

    def encrypt_v2(
        self,
        input_path: str,
        output_path: str,
        password: str,
        progress_cb=None,
    ) -> bytes:
        """
        Encrypt `input_path` → `output_path` using the v2 format.

        Steps
        -----
        1. Read plaintext from disk.
        2. Generate a fresh 16-byte random salt.
        3. Stretch the password with PBKDF2 (200,000 iterations).
        4. Derive fractal keystream from the stretched key.
        5. Build Julia S-Box from the stretched key.
        6. Apply S-Box substitution.
        7. XOR with fractal keystream.
        8. Compute HMAC-SHA256 over original plaintext.
        9. Write v2 header + ciphertext to output_path.

        Parameters
        ----------
        input_path : str
            Path to the plaintext file to encrypt.
        output_path : str
            Destination path for the .fractal v2 file.
        password : str
            User passphrase.
        progress_cb : callable or None
            Optional progress callback (receives float in [0.0, 1.0]).

        Returns
        -------
        bytes
            The 16-byte random salt that was used (stored in header).

        Raises
        ------
        FileNotFoundError
            If `input_path` does not exist.
        PermissionError
            If `output_path` cannot be written.
        """
        if not os.path.isfile(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path!r}")

        with open(input_path, "rb") as fh:
            plaintext = fh.read()

        original_name = os.path.basename(input_path).encode("utf-8")
        pt_len        = len(plaintext)

        self._log(f"  [v2] Encrypting {input_path!r}  ({pt_len:,} bytes)")

        # ── Generate fresh random salt ────────────────────────────────────────
        salt = os.urandom(SALT_BYTES)
        self._log(f"  [·]  Salt: {salt.hex()}")

        # ── PBKDF2 key stretching ─────────────────────────────────────────────
        self._log(f"  [·]  PBKDF2 stretching ({PBKDF2_ITERATIONS:,} iterations)…")
        stretched_key = stretch_password(password, salt)

        # ── Fractal keystream (Mandelbrot) ────────────────────────────────────
        self._log("  [·]  Generating fractal keystream…")
        keystream = self.engine.mandelbrot_keystream(stretched_key, pt_len)

        # ── Julia S-Box ───────────────────────────────────────────────────────
        self._log("  [·]  Building Julia S-Box…")
        sbox = self.engine.julia_sbox(stretched_key)

        # ── S-Box substitution ────────────────────────────────────────────────
        substituted = self._apply_sbox(plaintext, sbox)

        # ── XOR with keystream ────────────────────────────────────────────────
        ciphertext = self._xor_with_keystream(substituted, keystream, progress_cb)

        # ── HMAC over original plaintext ──────────────────────────────────────
        seed = self.engine._derive_seed(stretched_key)
        mac  = self._compute_hmac(seed, plaintext)

        # ── Write v2 file ─────────────────────────────────────────────────────
        with open(output_path, "wb") as fh:
            fh.write(MAGIC_HEADER)                            # [8]  magic
            fh.write(salt)                                    # [16] random salt
            fh.write(struct.pack(">I", len(original_name)))  # [4]  name len
            fh.write(original_name)                          # [N]  filename
            fh.write(mac)                                    # [32] HMAC
            fh.write(struct.pack(">I", pt_len))              # [4]  pt len
            fh.write(ciphertext)                             # [M]  ciphertext

        self._log(f"  [✓]  Encrypted → {output_path!r}")
        return salt

    def encrypt_v2_bytes(
        self,
        plaintext: bytes,
        filename: str,
        password: str,
        progress_cb=None,
    ) -> bytes:
        """
        Encrypt raw bytes (no file I/O) and return the v2 encrypted blob.

        Useful for in-memory operations such as folder-mode zip encryption.

        Parameters
        ----------
        plaintext : bytes
            Raw plaintext data to encrypt.
        filename : str
            Logical filename to embed in the header.
        password : str
            User passphrase.
        progress_cb : callable or None
            Optional progress callback.

        Returns
        -------
        bytes
            Complete v2 encrypted blob (magic + salt + header + ciphertext).
        """
        pt_len        = len(plaintext)
        original_name = filename.encode("utf-8")

        salt          = os.urandom(SALT_BYTES)
        stretched_key = stretch_password(password, salt)
        keystream     = self.engine.mandelbrot_keystream(stretched_key, pt_len)
        sbox          = self.engine.julia_sbox(stretched_key)
        substituted   = self._apply_sbox(plaintext, sbox)
        ciphertext    = self._xor_with_keystream(substituted, keystream, progress_cb)
        seed          = self.engine._derive_seed(stretched_key)
        mac           = self._compute_hmac(seed, plaintext)

        import io
        buf = io.BytesIO()
        buf.write(MAGIC_HEADER)
        buf.write(salt)
        buf.write(struct.pack(">I", len(original_name)))
        buf.write(original_name)
        buf.write(mac)
        buf.write(struct.pack(">I", pt_len))
        buf.write(ciphertext)
        return buf.getvalue()

    def decrypt_v2(
        self,
        input_path: str,
        output_path: str,
        password: str,
        progress_cb=None,
    ) -> str:
        """
        Decrypt a v2 .fractal file → `output_path`.

        Steps
        -----
        1. Read and parse the v2 header (magic + salt + filename + HMAC + length).
        2. Re-derive the same stretched key using PBKDF2 with the stored salt.
        3. Reverse XOR and inverse S-Box to recover plaintext.
        4. Verify HMAC — raise ValueError on mismatch.
        5. Write plaintext to output_path.

        Parameters
        ----------
        input_path : str
            Path to the v2 .fractal encrypted file.
        output_path : str
            Destination path for the decrypted plaintext.
        password : str
            User passphrase (must match the one used to encrypt).
        progress_cb : callable or None
            Optional progress callback (float in [0.0, 1.0]).

        Returns
        -------
        str
            The original filename embedded in the header.

        Raises
        ------
        FileNotFoundError
            If `input_path` does not exist.
        ValueError
            If the magic header is invalid or HMAC verification fails.
        struct.error
            If the file is truncated or structurally corrupt.
        """
        if not os.path.isfile(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path!r}")

        with open(input_path, "rb") as fh:
            raw = fh.read()

        original_name = self._decrypt_v2_bytes(raw, password, progress_cb)

        plaintext = self._last_plaintext  # set by _decrypt_v2_bytes
        with open(output_path, "wb") as fh:
            fh.write(plaintext)

        self._log(f"  [✓]  Decrypted → {output_path!r}")
        return original_name

    def decrypt_v2_bytes(
        self,
        blob: bytes,
        password: str,
        progress_cb=None,
    ) -> tuple:
        """
        Decrypt a v2 encrypted blob in memory (no file I/O).

        Parameters
        ----------
        blob : bytes
            Complete v2 encrypted blob.
        password : str
            User passphrase.
        progress_cb : callable or None
            Optional progress callback.

        Returns
        -------
        tuple[str, bytes]
            (original_filename, plaintext_bytes)

        Raises
        ------
        ValueError
            On invalid magic or HMAC failure.
        """
        original_name = self._decrypt_v2_bytes(blob, password, progress_cb)
        return original_name, self._last_plaintext

    def _decrypt_v2_bytes(
        self,
        raw: bytes,
        password: str,
        progress_cb=None,
    ) -> str:
        """
        Internal: parse v2 blob, verify HMAC, and recover plaintext.

        Stores the decrypted plaintext in ``self._last_plaintext`` for the
        caller to retrieve.

        Parameters
        ----------
        raw : bytes
            Raw v2 encrypted data (starting with magic header).
        password : str
            User passphrase.
        progress_cb : callable or None
            Optional progress callback.

        Returns
        -------
        str
            Original filename extracted from header.

        Raises
        ------
        ValueError
            On magic mismatch or HMAC failure.
        """
        offset = 0

        # Magic
        magic = raw[offset:offset + 8]
        offset += 8
        if magic != MAGIC_HEADER:
            raise ValueError(
                f"Invalid magic header {magic!r}. "
                "Not a valid .fractal v2 file."
            )

        # Salt (v2 has 16 bytes after magic)
        salt = raw[offset:offset + SALT_BYTES]
        offset += SALT_BYTES

        # Original filename
        name_len = struct.unpack_from(">I", raw, offset)[0]
        offset  += 4
        original_name = raw[offset:offset + name_len].decode("utf-8")
        offset  += name_len

        # HMAC
        stored_mac = raw[offset:offset + 32]
        offset     += 32

        # Plaintext length
        pt_len  = struct.unpack_from(">I", raw, offset)[0]
        offset += 4

        # Ciphertext
        ciphertext = raw[offset:offset + pt_len]
        if len(ciphertext) != pt_len:
            raise ValueError(
                f"File truncated: expected {pt_len} bytes, got {len(ciphertext)}."
            )

        self._log(f"  [v2] Decrypting, original filename: {original_name!r}")

        # ── Re-derive key from stored salt ────────────────────────────────────
        self._log(f"  [·]  PBKDF2 re-stretching ({PBKDF2_ITERATIONS:,} iterations)…")
        stretched_key = stretch_password(password, salt)

        # ── Re-build keystream + S-Box ────────────────────────────────────────
        keystream = self.engine.mandelbrot_keystream(stretched_key, pt_len)
        sbox      = self.engine.julia_sbox(stretched_key)
        inv_sbox  = self.engine.inverse_sbox(sbox)

        # ── Reverse pipeline ──────────────────────────────────────────────────
        substituted = self._xor_with_keystream(ciphertext, keystream, progress_cb)
        plaintext   = self._apply_sbox(substituted, inv_sbox)

        # ── HMAC verification ─────────────────────────────────────────────────
        seed         = self.engine._derive_seed(stretched_key)
        computed_mac = self._compute_hmac(seed, plaintext)
        if not hmac.compare_digest(computed_mac, stored_mac):
            raise ValueError(
                "HMAC verification FAILED.\n"
                "The file may be tampered with, or the password is wrong."
            )

        self._log("  [✓]  HMAC verified — integrity confirmed")
        self._last_plaintext = plaintext
        return original_name


# ─────────────────────────────────────────────────────────────────────────────
# CONVENIENCE MODULE-LEVEL FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def encrypt_v2(input_path: str, output_path: str, password: str) -> None:
    """
    Module-level convenience function for v2 encryption.

    Parameters
    ----------
    input_path : str
        Path to the plaintext file.
    output_path : str
        Destination path for the .fractal v2 file.
    password : str
        User passphrase.
    """
    FractalCipherV2(verbose=False).encrypt_v2(input_path, output_path, password)


def decrypt_v2(input_path: str, output_path: str, password: str) -> None:
    """
    Module-level convenience function for v2 decryption.

    Parameters
    ----------
    input_path : str
        Path to the v2 .fractal encrypted file.
    output_path : str
        Destination path for the decrypted output.
    password : str
        User passphrase.
    """
    FractalCipherV2(verbose=False).decrypt_v2(input_path, output_path, password)
