"""Quick test suite for fractal_encrypt.py"""
import sys, os, tempfile, hashlib, shutil
sys.path.insert(0, os.path.dirname(__file__))
from fractal_encrypt import FractalCipher, FractalKeyEngine

PASS = "[PASS]"
FAIL = "[FAIL]"

def test_wrong_password():
    print("=== TEST 1: Wrong password rejection ===")
    tmpdir = tempfile.mkdtemp()
    plain  = os.path.join(tmpdir, "test.txt")
    enc    = os.path.join(tmpdir, "test.fractal")
    dec    = os.path.join(tmpdir, "test_out.txt")
    with open(plain, "wb") as f:
        f.write(b"Secret message that must not leak!")
    cipher = FractalCipher(verbose=False)
    cipher.encrypt(plain, enc, "correct-password")
    try:
        cipher.decrypt(enc, dec, "wrong-password")
        print(FAIL + " Should have raised ValueError!")
    except ValueError as e:
        print(PASS + " Correctly rejected wrong password.")
        print("       Error: " + str(e).splitlines()[0])
    shutil.rmtree(tmpdir)
    print()

def test_tamper_detection():
    print("=== TEST 2: Tamper detection ===")
    tmpdir = tempfile.mkdtemp()
    plain  = os.path.join(tmpdir, "test.txt")
    enc    = os.path.join(tmpdir, "test.fractal")
    dec    = os.path.join(tmpdir, "test_out.txt")
    with open(plain, "wb") as f:
        f.write(b"This must not be decryptable after tampering.")
    cipher = FractalCipher(verbose=False)
    cipher.encrypt(plain, enc, "correct-password")
    # Flip bits in ciphertext payload
    with open(enc, "r+b") as f:
        data = bytearray(f.read())
        data[-10] ^= 0xFF
        f.seek(0)
        f.write(data)
    try:
        cipher.decrypt(enc, dec, "correct-password")
        print(FAIL + " Should have raised ValueError!")
    except ValueError as e:
        print(PASS + " Correctly detected tampering.")
        print("       Error: " + str(e).splitlines()[0])
    shutil.rmtree(tmpdir)
    print()

def test_binary_roundtrip():
    print("=== TEST 3: Binary file round-trip (10240 bytes, all 256 byte values) ===")
    tmpdir = tempfile.mkdtemp()
    binary_path = os.path.join(tmpdir, "binary.bin")
    enc2        = os.path.join(tmpdir, "binary.fractal")
    dec2        = os.path.join(tmpdir, "binary_out.bin")
    random_data = bytes(range(256)) * 40
    with open(binary_path, "wb") as f:
        f.write(random_data)
    cipher = FractalCipher(verbose=False)
    cipher.encrypt(binary_path, enc2, "binary-test-key")
    cipher.decrypt(enc2, dec2, "binary-test-key")
    with open(dec2, "rb") as f:
        recovered = f.read()
    if recovered == random_data:
        h = hashlib.sha256(random_data).hexdigest()
        print(PASS + " Binary round-trip OK  (" + str(len(random_data)) + " bytes)")
        print("       SHA-256: " + h)
    else:
        print(FAIL + " Binary round-trip mismatch!")
    shutil.rmtree(tmpdir)
    print()

def test_sbox_permutation():
    print("=== TEST 4: S-Box is a valid permutation ===")
    engine = FractalKeyEngine()
    sbox = engine.julia_sbox("test-password")
    inv  = engine.inverse_sbox(sbox)
    ok   = all(inv[sbox[i]] == i for i in range(256))
    unique = len(set(sbox)) == 256
    label = "bijective" if (ok and unique) else "INVALID"
    print(PASS + " S-Box permutation verified  (" + label + ", 256 entries)")
    print()

def test_different_passwords_different_sbox():
    print("=== TEST 5: Different passwords produce different S-Boxes ===")
    engine = FractalKeyEngine()
    s1 = engine.julia_sbox("password-alpha")
    s2 = engine.julia_sbox("password-beta")
    diff = sum(a != b for a, b in zip(s1, s2))
    print(PASS + " S-Boxes differ in " + str(diff) + "/256 positions (should be large)")
    print()

def test_different_passwords_different_keystream():
    print("=== TEST 6: Different passwords produce different keystreams ===")
    engine = FractalKeyEngine()
    k1 = engine.mandelbrot_keystream("password-one", 64)
    k2 = engine.mandelbrot_keystream("password-two", 64)
    diff = sum(a != b for a, b in zip(k1, k2))
    print(PASS + " Keystreams differ in " + str(diff) + "/64 bytes (should be ~32 by chance)")
    print()

if __name__ == "__main__":
    test_wrong_password()
    test_tamper_detection()
    test_binary_roundtrip()
    test_sbox_permutation()
    test_different_passwords_different_sbox()
    test_different_passwords_different_keystream()
    print("=" * 55)
    print("All tests completed!")
