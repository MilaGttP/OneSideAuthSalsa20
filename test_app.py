"""
test_app.py - Simple pytest tests for the Salsa20 auth demo.
Run with: python -m pytest test_app.py -v
"""
import struct
import pytest
from salsa20_core import quarter_round, salsa20_encrypt, salsa20_decrypt, build_state
from app import app

KEY   = bytes(range(32))
NONCE = bytes(range(8))

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as c:
        yield c

# --- salsa20_core ---

def test_quarter_round_changes_values():
    a, b, c, d = quarter_round(1, 2, 3, 4)
    assert (a, b, c, d) != (1, 2, 3, 4)

def test_quarter_round_known_vector():
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

def test_ciphertext_differs_from_plaintext():
    msg = b"test message"
    ct, _ = salsa20_encrypt(KEY, NONCE, msg)
    assert ct != msg

def test_different_keys_give_different_ciphertext():
    msg = b"same plaintext"
    ct1, _ = salsa20_encrypt(KEY, NONCE, msg)
    ct2, _ = salsa20_encrypt(bytes([0xFF]*32), NONCE, msg)
    assert ct1 != ct2

def test_ciphertext_same_length_as_plaintext():
    msg = b"length check!!"
    ct, _ = salsa20_encrypt(KEY, NONCE, msg)
    assert len(ct) == len(msg)

def test_build_state_is_16_words():
    assert len(build_state(KEY, NONCE, 0)) == 16

def test_wrong_key_cannot_decrypt():
    msg = b"secret"
    ct, _ = salsa20_encrypt(KEY, NONCE, msg)
    pt, _ = salsa20_decrypt(bytes([0xFF]*32), NONCE, ct)
    assert pt != msg

# --- Flask API ---

def test_index_ok(client):
    assert client.get('/').status_code == 200

def test_prepare_ok(client):
    r = client.post('/api/step/prepare', json={'key': KEY.hex(), 'server_id': 'TEST'})
    assert r.status_code == 200
    assert 'timestamp' in r.get_json()

def test_prepare_bad_key(client):
    r = client.post('/api/step/prepare', json={'key': 'zzzz', 'server_id': 'TEST'})
    assert r.status_code == 400

def test_prepare_key_too_short(client):
    r = client.post('/api/step/prepare', json={'key': 'aabb', 'server_id': 'TEST'})
    assert r.status_code == 400

def test_prepare_server_id_too_long(client):
    r = client.post('/api/step/prepare', json={'key': KEY.hex(), 'server_id': 'A'*33})
    assert r.status_code == 400

def test_prepare_empty_server_id(client):
    r = client.post('/api/step/prepare', json={'key': KEY.hex(), 'server_id': ''})
    assert r.status_code == 400

def test_encrypt_ok(client):
    r = client.post('/api/step/encrypt', json={
        'key': KEY.hex(), 'nonce': NONCE.hex(), 'plaintext_hex': (b'\x00'*40).hex()
    })
    assert r.status_code == 200
    data = r.get_json()
    assert len(data['initial_matrix']) == 4

def test_authenticate_granted(client):
    sid = 'SERVER-01'
    plaintext = struct.pack('>Q', 9999999999) + sid.encode().ljust(32, b'\x00')
    ct, _ = salsa20_encrypt(KEY, NONCE, plaintext)
    r = client.post('/api/step/authenticate', json={
        'key': KEY.hex(), 'nonce': NONCE.hex(),
        'ciphertext_hex': ct.hex(), 'server_id': sid, 'delta_t': 9999999999
    })
    data = r.get_json()
    assert data['id_match'] is True
    assert data['access_granted'] is True

def test_authenticate_wrong_id(client):
    sid = 'SERVER-01'
    plaintext = struct.pack('>Q', 9999999999) + sid.encode().ljust(32, b'\x00')
    ct, _ = salsa20_encrypt(KEY, NONCE, plaintext)
    r = client.post('/api/step/authenticate', json={
        'key': KEY.hex(), 'nonce': NONCE.hex(),
        'ciphertext_hex': ct.hex(), 'server_id': 'WRONG', 'delta_t': 9999999999
    })
    data = r.get_json()
    assert data['id_match'] is False
    assert data['access_granted'] is False

def test_authenticate_expired_timestamp(client):
    sid = 'SERVER-01'
    plaintext = struct.pack('>Q', 1) + sid.encode().ljust(32, b'\x00')
    ct, _ = salsa20_encrypt(KEY, NONCE, plaintext)
    r = client.post('/api/step/authenticate', json={
        'key': KEY.hex(), 'nonce': NONCE.hex(),
        'ciphertext_hex': ct.hex(), 'server_id': sid, 'delta_t': 30
    })
    data = r.get_json()
    assert data['time_ok'] is False
    assert data['access_granted'] is False
