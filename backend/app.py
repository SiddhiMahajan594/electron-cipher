from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import base64
import math
import time
import json
from collections import Counter

app = Flask(__name__)
CORS(app)

# ─── Orbital Configuration ────────────────────────────────────────────────────
orbital_order = [('s', 2), ('p', 6), ('d', 10), ('f', 14)]

# ─── Key Derivation ───────────────────────────────────────────────────────────
def derive_key_from_password(password, salt=None):
    if salt is None:
        salt = get_random_bytes(16)
    password_bytes = password.encode() if isinstance(password, str) else password
    key = PBKDF2(password_bytes, salt, dkLen=32, count=100000)
    return key, salt

# ─── Dynamic S-box Generation (key-dependent via SHA-256) ────────────────────
def generate_dynamic_sboxes(key):
    """
    Generates key-dependent orbital S-boxes using SHA-256(key || orbital_name).
    Each password produces unique permutations — eliminates static mapping vulnerabilities.
    """
    dynamic_sboxes = {}
    orbital_lengths = {'s': 2, 'p': 6, 'd': 10, 'f': 14}
    for orbital, length in orbital_lengths.items():
        h = SHA256.new(key + orbital.encode()).digest()
        indices = list(range(length))
        # Fisher-Yates shuffle driven by hash digest bytes
        for i in range(len(h)):
            j = i % length
            k = h[i] % length
            indices[j], indices[k] = indices[k], indices[j]
        dynamic_sboxes[orbital] = indices
    return dynamic_sboxes

def generate_inverse_sboxes(sboxes):
    inv_sboxes = {}
    for orbital, sbox in sboxes.items():
        inv = [0] * len(sbox)
        for i, val in enumerate(sbox):
            inv[val] = i
        inv_sboxes[orbital] = inv
    return inv_sboxes

# ─── Orbital Permutation ─────────────────────────────────────────────────────
def orbital_permute(binary, sboxes):
    result = ''
    idx = 0
    order_idx = 0
    mappings = []

    while idx < len(binary):
        orbital, bits = orbital_order[order_idx % len(orbital_order)]
        sbox = sboxes[orbital]
        segment = binary[idx:idx + bits]
        if len(segment) < bits:
            segment = segment.ljust(bits, '0')
        permuted = ''.join(segment[sbox[i]] if i < len(segment) else '0' for i in range(bits))
        result += permuted
        mappings.append((orbital, segment, permuted))
        idx += bits
        order_idx += 1

    return result, mappings

def orbital_unpermute(binary, inv_sboxes):
    result = ''
    idx = 0
    order_idx = 0

    while idx < len(binary):
        orbital, bits = orbital_order[order_idx % len(orbital_order)]
        inv_sbox = inv_sboxes[orbital]
        segment = binary[idx:idx + bits]
        if len(segment) < bits:
            segment = segment.ljust(bits, '0')
        unpermuted = ['0'] * bits
        for i in range(bits):
            src_idx = inv_sbox[i]
            if src_idx < len(segment):
                unpermuted[i] = segment[src_idx]
        result += ''.join(unpermuted)
        idx += bits
        order_idx += 1

    return result

# ─── Binary / Byte Utilities ──────────────────────────────────────────────────
def binary_to_bytes(binary):
    padding = (8 - len(binary) % 8) % 8
    padded = binary + '0' * padding
    byte_array = bytearray()
    for i in range(0, len(padded), 8):
        byte = padded[i:i+8]
        byte_array.append(int(byte, 2))
    return bytes(byte_array)

def bytes_to_binary(byte_data, length=None):
    binary = ''.join(format(b, '08b') for b in byte_data)
    if length is not None:
        binary = binary[:length]
    return binary

# ─── Core Encrypt / Decrypt ───────────────────────────────────────────────────
def encrypt_with_orbitals(plaintext, password):
    key, salt = derive_key_from_password(password)
    iv = get_random_bytes(16)
    plaintext_bytes = plaintext.encode()
    binary = ''.join(format(byte, '08b') for byte in plaintext_bytes)

    sboxes = generate_dynamic_sboxes(key)
    permuted_binary, mappings = orbital_permute(binary, sboxes)

    byte_data = binary_to_bytes(permuted_binary)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(byte_data, AES.block_size))

    length_bytes = len(binary).to_bytes(4, byteorder='big')
    result = salt + iv + length_bytes + encrypted
    return base64.b64encode(result).decode(), mappings, binary, permuted_binary

def decrypt_with_orbitals(ciphertext_b64, password):
    try:
        raw = base64.b64decode(ciphertext_b64)
        salt = raw[:16]
        iv = raw[16:32]
        original_length = int.from_bytes(raw[32:36], byteorder='big')
        encrypted = raw[36:]
    except Exception as e:
        return None, f"Parse error: {e}"

    key, _ = derive_key_from_password(password, salt)
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted)
        decrypted = unpad(decrypted_padded, AES.block_size)
    except Exception as e:
        return None, f"Decryption error: {e}"

    decrypted_binary = bytes_to_binary(decrypted)
    sboxes = generate_dynamic_sboxes(key)
    inv_sboxes = generate_inverse_sboxes(sboxes)
    original_binary = orbital_unpermute(decrypted_binary, inv_sboxes)
    original_binary = original_binary[:original_length]

    try:
        padded = original_binary
        if len(padded) % 8 != 0:
            padded = padded + '0' * (8 - len(padded) % 8)
        bytes_array = bytearray()
        for i in range(0, len(padded), 8):
            if i + 8 <= len(padded):
                bytes_array.append(int(padded[i:i+8], 2))
        return bytes(bytes_array).decode('utf-8', errors='replace'), None
    except Exception as e:
        return None, f"Decode error: {e}"

# ─── Experiment: Avalanche Effect ─────────────────────────────────────────────
def hamming_distance(b1, b2):
    return sum(c1 != c2 for c1, c2 in zip(b1, b2))

def run_avalanche_test(plaintext, password, trials=50):
    results = []
    for _ in range(trials):
        try:
            ct1, _, _, _ = encrypt_with_orbitals(plaintext, password)
            modified = plaintext[:-1] + chr(ord(plaintext[-1]) ^ 1) if plaintext else 'A'
            ct2, _, _, _ = encrypt_with_orbitals(modified, password)

            raw1 = base64.b64decode(ct1)[36:]
            raw2 = base64.b64decode(ct2)[36:]
            bits1 = bytes_to_binary(raw1)
            bits2 = bytes_to_binary(raw2)
            minlen = min(len(bits1), len(bits2))
            if minlen > 0:
                score = hamming_distance(bits1[:minlen], bits2[:minlen]) / minlen * 100
                results.append(round(score, 2))
        except:
            continue

    if not results:
        return {"mean": 0, "std": 0, "trials": 0, "scores": []}

    mean = sum(results) / len(results)
    variance = sum((x - mean) ** 2 for x in results) / len(results)
    std = variance ** 0.5
    return {
        "mean": round(mean, 2),
        "std": round(std, 2),
        "trials": len(results),
        "scores": results
    }

# ─── Experiment: Shannon Entropy ──────────────────────────────────────────────
def shannon_entropy(data_bytes):
    if not data_bytes:
        return 0.0
    counts = Counter(data_bytes)
    total = len(data_bytes)
    return round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 4)

def run_entropy_test(plaintext, password):
    ciphertext_b64, _, orig_binary, perm_binary = encrypt_with_orbitals(plaintext, password)
    raw = base64.b64decode(ciphertext_b64)
    aes_bytes = raw[36:]

    plaintext_bytes = plaintext.encode()
    permuted_bytes = binary_to_bytes(perm_binary)

    return {
        "plaintext_entropy": shannon_entropy(plaintext_bytes),
        "permuted_entropy": shannon_entropy(permuted_bytes),
        "aes_ciphertext_entropy": shannon_entropy(aes_bytes),
        "max_possible": 8.0
    }

# ─── Experiment: Timing Overhead ──────────────────────────────────────────────
def run_timing_test(password):
    sizes = [64, 128, 512, 1024, 4096]
    results = []
    for size in sizes:
        plaintext = 'A' * size
        runs = []
        for _ in range(3):
            start = time.perf_counter()
            encrypt_with_orbitals(plaintext, password)
            elapsed = (time.perf_counter() - start) * 1000
            runs.append(round(elapsed, 3))
        results.append({
            "size_bytes": size,
            "avg_ms": round(sum(runs) / len(runs), 3),
            "min_ms": round(min(runs), 3),
            "max_ms": round(max(runs), 3)
        })
    return results

# ─── Flask Routes ─────────────────────────────────────────────────────────────
@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    data = request.json
    plaintext = data.get('plaintext', '')
    password = data.get('password', '')

    if not plaintext or not password:
        return jsonify({"error": "Plaintext and password are required"}), 400

    try:
        ciphertext, mappings, orig_binary, perm_binary = encrypt_with_orbitals(plaintext, password)
        mappings_serializable = [
            {"orbital": m[0], "before": m[1], "after": m[2]}
            for m in mappings[:20]  # limit for frontend
        ]
        return jsonify({
            "ciphertext": ciphertext,
            "original_bits": orig_binary[:256],  # preview
            "permuted_bits": perm_binary[:256],
            "mappings": mappings_serializable,
            "original_length": len(orig_binary),
            "permuted_length": len(perm_binary)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    data = request.json
    ciphertext = data.get('ciphertext', '')
    password = data.get('password', '')

    if not ciphertext or not password:
        return jsonify({"error": "Ciphertext and password are required"}), 400

    try:
        plaintext, error = decrypt_with_orbitals(ciphertext, password)
        if error:
            return jsonify({"error": error}), 400
        return jsonify({"plaintext": plaintext})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/experiments/avalanche', methods=['POST'])
def api_avalanche():
    data = request.json
    plaintext = data.get('plaintext', 'Hello World')
    password = data.get('password', 'test')
    trials = min(int(data.get('trials', 30)), 50)
    result = run_avalanche_test(plaintext, password, trials)
    return jsonify(result)

@app.route('/api/experiments/entropy', methods=['POST'])
def api_entropy():
    data = request.json
    plaintext = data.get('plaintext', 'Hello World')
    password = data.get('password', 'test')
    result = run_entropy_test(plaintext, password)
    return jsonify(result)

@app.route('/api/experiments/timing', methods=['POST'])
def api_timing():
    data = request.json
    password = data.get('password', 'test')
    result = run_timing_test(password)
    return jsonify(result)

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "version": "2.0"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
