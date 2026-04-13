"""
test_app.py — Simple pytest tests for the Salsa20 auth demo.
Run with: pytest test_app.py -v
"""

import struct
import pytest
from salsa20_core import quarter_round, salsa20_encrypt, salsa20_decrypt, build_state
from app import app


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as c:
        yield c

KEY   = bytes(range(32))        # 32 bytes: 00 01 02 ... 1f
NONCE = bytes(range(8))         # 8 bytes:  00 01 ... 07


# ── salsa20_core tests ────────────────────────────────────────────────────

def test_quarter_round_changes_values():
    a, b, c, d = quarter_round(1, 2, 3, 4)
    # output must differ from input
    assert (a, b, c, d) != (1, 2, 3, 4)

def test_quarter_round_known_vector():
    # Official Salsa20 test vector from the spec
    a, b, c, d = quarter_round(0x00000001, 0x00000000, 0x00000000, 0x00000000)
    assert a == 0x08008145
    assert b == 0x00000080
    assert c == 0x00010200
    assert d == 0x20500000

def test_encrypt_decrypt_roundtrip():
    msg = b"Hello, Salsa20!"
    ct, _ = salsa20_encrypt(KEY, NONCE, msg)
    pt, _ = salsa20_decrypt(KEY, NONCE, ct)
    assert pt == msg

def test_encrypt_produces_different_bytes():
    msg = b"test message"
    ct, _ = salsa20_encrypt(KEY, NONCE, msg)
    assert ct != msg

def test_different_keys_give_different_ciphertext():
    msg = b"same plaintext"
    key2 = bytes([255] * 32)
    ct1, _ = salsa20_encrypt(KEY,  NONCE, msg)
    ct2, _ = salsa20_encrypt(key2, NONCE, msg)
    assert ct1 != ct2

def test_ciphertext_same_length_as_plaintext():
    msg = b"length check!!"
    ct, _ = salsa20_encrypt(KEY, NONCE, msg)
    assert len(ct) == len(msg)

def test_build_state_length():
    state = build_state(KEY, NONCE, 0)
    assert len(state) == 16

def test_wrong_key_cannot_decrypt():
    msg = b"secret"
    ct, _ = salsa20_encrypt(KEY, NONCE, msg)
    wrong_key = bytes([0xFF] * 32)
    pt, _ = salsa20_decrypt(wrong_key, NONCE, ct)
    assert pt != msg


# ── Flask API tests ───────────────────────────────────────────────────────

def test_index_returns_200(client):
    r = client.get('/')
    assert r.status_code == 200

def test_prepare_ok(client):
    r = client.post('/api/step/prepare', json={
        'key': KEY.hex(),
        'server_id': 'TEST-SERVER'
    })
    assert r.status_code == 200
    data = r.get_json()
    assert 'timestamp' in data
    assert 'plaintext_hex' in data

def test_prepare_bad_key(client):
    r = client.post('/api/step/prepare', json={
        'key': 'notahexkey',
        'server_id': 'TEST-SERVER'
    })
    assert r.status_code == 400

def test_prepare_short_key(client):
    r = client.post('/api/step/prepare', json={
        'key': 'aabb',          # too short
        'server_id': 'TEST-SERVER'
    })
    assert r.status_code == 400

def test_prepare_server_id_too_long(client):
    r = client.post('/api/step/prepare', json={
        'key': KEY.hex(),
        'server_id': 'A' * 33   # 33 bytes — over the limit
    })
    assert r.status_code == 400

def test_prepare_missing_server_id(client):
    r = client.post('/api/step/prepare', json={
        'key': KEY.hex(),
        'server_id': ''
    })
    assert r.status_code == 400

def test_encrypt_ok(client):
    plaintext = b'\x00' * 40
    r = client.post('/api/step/encrypt', json={
        'key':           KEY.hex(),
        'nonce':         NONCE.hex(),
        'plaintext_hex': plaintext.hex()
    })
    assert r.status_code == 200
    data = r.get_json()
    assert 'ciphertext_hex' in data
    assert 'initial_matrix' in data
    assert len(data['initial_matrix']) == 4      # 4x4 matrix

def test_authenticate_access_granted(client):
    server_id = 'SERVER-01'
    # Build the same plaintext the real flow would use
    t_a = 9999999999                             # far-future timestamp
    plaintext = struct.pack('>Q', t_a) + server_id.encode().ljust(32, b'\x00')
    ct, _ = salsa20_encrypt(KEY, NONCE, plaintext)

    r = client.post('/api/step/authenticate', json={
        'key':            KEY.hex(),
        'nonce':          NONCE.hex(),
        'ciphertext_hex': ct.hex(),
        'server_id':      server_id,
        'delta_t':        9999999999              # huge window so time always passes
    })
    assert r.status_code == 200
    data = r.get_json()
    assert data['id_match'] is True
    assert data['access_granted'] is True

def test_authenticate_wrong_server_id(client):
    server_id = 'SERVER-01'
    t_a = 9999999999
    plaintext = struct.pack('>Q', t_a) + server_id.encode().ljust(32, b'\x00')
    ct, _ = salsa20_encrypt(KEY, NONCE, plaintext)

    r = client.post('/api/step/authenticate', json={
        'key':            KEY.hex(),
        'nonce':          NONCE.hex(),
        'ciphertext_hex': ct.hex(),
        'server_id':      'WRONG-SERVER',        # mismatch
        'delta_t':        9999999999
    })
    data = r.get_json()
    assert data['id_match'] is False
    assert data['access_granted'] is False

def test_authenticate_expired_timestamp(client):
    server_id = 'SERVER-01'
    t_a = 1                                      # Unix epoch — ancient
    plaintext = struct.pack('>Q', t_a) + server_id.encode().ljust(32, b'\x00')
    ct, _ = salsa20_encrypt(KEY, NONCE, plaintext)

    r = client.post('/api/step/authenticate', json={
        'key':            KEY.hex(),
        'nonce':          NONCE.hex(),
        'ciphertext_hex': ct.hex(),
        'server_id':      server_id,
        'delta_t':        30                     # 30s window — will fail
    })
    data = r.get_json()
    assert data['time_ok'] is False
    assert data['access_granted'] is False
