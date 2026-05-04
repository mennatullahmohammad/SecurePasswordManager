import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))
import config
import module_1
import module_3

config.load_params()

priv, pub = module_1.initialize_user("testuser")
x = int(priv["x"])
q = int(pub["q"])
alpha = int(pub["alpha"])
y = int(pub["y"])

def test_sign_verify():
    vault_data = '{"encrypted_vault": "abc123fake"}'
    vault_hash = module_3.hash_vault(vault_data)
    r, s = module_3.sign(vault_hash, x, q, alpha)
    result = module_3.verify(r, s, vault_hash, y, alpha, q)
    assert result is True, "Valid signature should verify"
    print("Sign and verify works")

def test_tampered_vault():
    vault_data = '{"encrypted_vault": "abc123fake"}'
    vault_hash = module_3.hash_vault(vault_data)
    r, s = module_3.sign(vault_hash, x, q, alpha)

    tampered = '{"encrypted_vault": "abc123TAMPERED"}'
    tampered_hash = module_3.hash_vault(tampered)
    result = module_3.verify(r, s, tampered_hash, y, alpha, q)
    assert result is False, "Tampered vault should fail verification"
    print("Tampered vault correctly rejected")

def test_wrong_key():
    priv2, pub2 = module_1.initialize_user("otheruser")
    vault_data = '{"encrypted_vault": "abc123fake"}'
    vault_hash = module_3.hash_vault(vault_data)
    r, s = module_3.sign(vault_hash, x, q, alpha)
    y2 = int(pub2["y"])
    result = module_3.verify(r, s, vault_hash, y2, alpha, q)
    assert result is False, "Wrong public key should fail verification"
    print("Wrong public key correctly rejected")

def test_multiple_signatures_differ():
    vault_data = '{"encrypted_vault": "abc123fake"}'
    vault_hash = module_3.hash_vault(vault_data)
    r1, s1 = module_3.sign(vault_hash, x, q, alpha)
    r2, s2 = module_3.sign(vault_hash, x, q, alpha)
    assert (r1, s1) != (r2, s2), "Signatures should be randomized"
    print("Signatures are randomized (non-deterministic)")

test_sign_verify()
test_tampered_vault()
test_wrong_key()
test_multiple_signatures_differ()