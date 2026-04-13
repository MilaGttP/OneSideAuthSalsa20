"""
salsa20_core.py — Salsa20 stream cipher implemented from scratch.
Uses the ARX (Addition, Rotation, XOR) architecture with 20 rounds.
No external crypto libraries used for core logic.
"""

import struct

def add32(a, b):
    """32-bit modular addition (the 'A' in ARX)."""
    return (a + b) & 0xFFFFFFFF

def rotl32(v, n):
    """32-bit left rotation by n bits (the 'R' in ARX)."""
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def xor32(a, b):
    """32-bit XOR (the 'X' in ARX)."""
    return a ^ b


def quarter_round(a, b, c, d):
    """
    Salsa20 quarter-round function.
    Mixes four 32-bit words using ARX operations.
    Returns the updated (a, b, c, d).
    """
    b = xor32(b, rotl32(add32(a, d),  7))
    c = xor32(c, rotl32(add32(b, a),  9))
    d = xor32(d, rotl32(add32(c, b), 13))
    a = xor32(a, rotl32(add32(d, c), 18))
    return a, b, c, d


def salsa20_block(state):
    """
    Applies 20 rounds (10 double-rounds) of the Salsa20 core to a 16-word state.
    Each double-round consists of a column round followed by a row round.
    Returns the final 16-word output block.
    """
    x = list(state) 

    for _ in range(10):

        # --- Column round ---
        x[ 0], x[ 4], x[ 8], x[12] = quarter_round(x[ 0], x[ 4], x[ 8], x[12])
        x[ 5], x[ 9], x[13], x[ 1] = quarter_round(x[ 5], x[ 9], x[13], x[ 1])
        x[10], x[14], x[ 2], x[ 6] = quarter_round(x[10], x[14], x[ 2], x[ 6])
        x[15], x[ 3], x[ 7], x[11] = quarter_round(x[15], x[ 3], x[ 7], x[11])

        # --- Row round ---
        x[ 0], x[ 1], x[ 2], x[ 3] = quarter_round(x[ 0], x[ 1], x[ 2], x[ 3])
        x[ 5], x[ 6], x[ 7], x[ 4] = quarter_round(x[ 5], x[ 6], x[ 7], x[ 4])
        x[10], x[11], x[ 8], x[ 9] = quarter_round(x[10], x[11], x[ 8], x[ 9])
        x[15], x[12], x[13], x[14] = quarter_round(x[15], x[12], x[13], x[14])

    # Add the original state back (feed-forward)
    return [add32(x[i], state[i]) for i in range(16)]


# Salsa20 "expand 32-byte k" constants (ASCII)
SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

def build_state(key: bytes, nonce: bytes, counter: int) -> list:
    """
    Build the 16-word (512-bit) Salsa20 initial state matrix:
      [sigma0, k0..k3, sigma1, nonce0, nonce1, ctr0, ctr1, sigma2, k4..k7, sigma3]

    Layout (4x4):
      0   1   2   3
      4   5   6   7
      8   9  10  11
     12  13  14  15
    """
    assert len(key) == 32, "Key must be 256 bits (32 bytes)"
    assert len(nonce) == 8, "Nonce must be 64 bits (8 bytes)"

    k = struct.unpack('<8I', key)    # 8 x 32-bit words from key
    n = struct.unpack('<2I', nonce)  # 2 x 32-bit words from nonce

    state = [
        SIGMA[0], k[0],    k[1],    k[2],
        k[3],     SIGMA[1], n[0],   n[1],
        counter & 0xFFFFFFFF, (counter >> 32) & 0xFFFFFFFF, SIGMA[2], k[4],
        k[5],     k[6],    k[7],    SIGMA[3],
    ]
    return state


def generate_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """
    Generate `length` bytes of Salsa20 keystream.
    Returns keystream bytes and the initial state (for visualization).
    """
    keystream = bytearray()
    counter = 0
    initial_state = None

    while len(keystream) < length:
        state = build_state(key, nonce, counter)
        if initial_state is None:
            initial_state = state[:]
        output_block = salsa20_block(state)
        block_bytes = struct.pack('<16I', *output_block)
        keystream.extend(block_bytes)
        counter += 1

    return bytes(keystream[:length]), initial_state


def salsa20_encrypt(key: bytes, nonce: bytes, plaintext: bytes):
    """
    Encrypt plaintext using Salsa20.
    Returns (ciphertext, initial_state_matrix).
    """
    keystream, initial_state = generate_keystream(key, nonce, len(plaintext))
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
    return ciphertext, initial_state


def salsa20_decrypt(key: bytes, nonce: bytes, ciphertext: bytes):
    """
    Decrypt ciphertext using Salsa20 (identical to encrypt — XOR is its own inverse).
    Returns (plaintext, initial_state_matrix).
    """
    return salsa20_encrypt(key, nonce, ciphertext)
