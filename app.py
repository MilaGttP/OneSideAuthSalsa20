"""
app.py — Flask backend for the One-Side Authentication Protocol visualization.
Implements the server-side (User B) logic: decrypt, verify Server ID, check timestamp.
"""

import os
import time
import struct
import json
from flask import Flask, request, jsonify, render_template

from salsa20_core import salsa20_encrypt, salsa20_decrypt, build_state, salsa20_block

app = Flask(__name__)

DELTA_T = int(os.environ.get("DELTA_T", 30))


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def hex_dump(data: bytes) -> str:
    """Return a formatted hex string (groups of 2, space-separated)."""
    return ' '.join(f'{b:02X}' for b in data)


def state_to_matrix(state: list) -> list:
    """Convert flat 16-word list to 4x4 matrix (list of lists) for display."""
    return [[f'{state[r*4 + c]:08X}' for c in range(4)] for r in range(4)]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/step/prepare', methods=['POST'])
def step_prepare():
    """
    Step 1 & 2 — User A side:
    Receive key + server_id, generate timestamp, build plaintext t_A || I_B.
    """
    data = request.get_json()
    key_hex = data.get('key', '')
    server_id = data.get('server_id', '')

    try:
        key_bytes = bytes.fromhex(key_hex)
        if len(key_bytes) != 32:
            return jsonify({'error': 'Key must be exactly 32 bytes (64 hex chars)'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid hex key'}), 400

    if not server_id:
        return jsonify({'error': 'Server ID is required'}), 400

    id_bytes = server_id.encode('utf-8')
    if len(id_bytes) > 32:
        return jsonify({'error': f'Server ID must be at most 32 bytes (got {len(id_bytes)})'}), 400

    t_a = int(time.time())
    t_a_bytes = struct.pack('>Q', t_a)

    plaintext = t_a_bytes + id_bytes.ljust(32, b'\x00')

    return jsonify({
        'timestamp': t_a,
        'timestamp_hex': hex_dump(t_a_bytes),
        'server_id_hex': hex_dump(id_bytes),
        'plaintext_hex': hex_dump(plaintext),
        'plaintext_len': len(plaintext),
    })


@app.route('/api/step/encrypt', methods=['POST'])
def step_encrypt():
    """
    Steps 3 & 4 — Salsa20 encryption + matrix visualization.
    Returns the initial state matrix, output block, and ciphertext hex dump.
    """
    data = request.get_json()
    key_hex = data.get('key', '')
    nonce_hex = data.get('nonce', '')
    plaintext_hex = data.get('plaintext_hex', '')

    try:
        key_bytes = bytes.fromhex(key_hex)
        nonce_bytes = bytes.fromhex(nonce_hex) if nonce_hex else os.urandom(8)
        plaintext = bytes.fromhex(plaintext_hex.replace(' ', ''))
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    initial_state = build_state(key_bytes, nonce_bytes, 0)
    output_block  = salsa20_block(list(initial_state))

    ciphertext, _ = salsa20_encrypt(key_bytes, nonce_bytes, plaintext)

    return jsonify({
        'nonce_hex': nonce_bytes.hex(),
        'initial_matrix': state_to_matrix(initial_state),
        'output_matrix': state_to_matrix(output_block),
        'ciphertext_hex': hex_dump(ciphertext),
        'ciphertext_b64': ciphertext.hex(),
    })


@app.route('/api/step/authenticate', methods=['POST'])
def step_authenticate():
    """
    Step 5 — User B (Server) side:
    Decrypt the packet, extract t_A and I_B*, compare with known I_B and current t_B.
    Decision: Access Granted if I_B* == I_B AND |t_B - t_A| <= Δt.
    """
    data = request.get_json()
    key_hex = data.get('key', '')
    nonce_hex = data.get('nonce', '')
    ciphertext_hex = data.get('ciphertext_hex', '')
    server_id = data.get('server_id', '')
    delta_t = int(data.get('delta_t', DELTA_T))

    try:
        key_bytes = bytes.fromhex(key_hex)
        nonce_bytes = bytes.fromhex(nonce_hex)
        ciphertext_bytes = bytes.fromhex(ciphertext_hex.replace(' ', ''))
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    plaintext, _ = salsa20_decrypt(key_bytes, nonce_bytes, ciphertext_bytes)

    t_a_extracted = struct.unpack('>Q', plaintext[:8])[0]
    id_extracted = plaintext[8:40].rstrip(b'\x00').decode('utf-8', errors='replace')

    t_b = int(time.time())
    delta_t_star = abs(t_b - t_a_extracted)

    id_match = (id_extracted == server_id)
    time_ok = (delta_t_star <= delta_t)
    access = id_match and time_ok

    return jsonify({
        'decrypted_hex': hex_dump(plaintext),
        't_a_extracted': t_a_extracted,
        'id_extracted': id_extracted,
        't_b': t_b,
        'delta_t_star': delta_t_star,
        'delta_t': delta_t,
        'id_match': id_match,
        'time_ok': time_ok,
        'access_granted': access,
    })


if __name__ == '__main__':
    app.run(debug=True, port=5000)
