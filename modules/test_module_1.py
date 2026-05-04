import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))

import config
import module_1

config.load_params()


def test_key_generation():
    priv, pub = module_1.initialize_user("testuser")

    assert os.path.exists("keys/testuser_private_key.json")
    assert os.path.exists("keys/testuser_public_key.json")

    assert "x" in priv
    assert "y" in pub
    assert "q" in pub
    assert "alpha" in pub
    assert "username" in pub

    x = int(priv["x"])
    y = int(pub["y"])
    q = int(pub["q"])
    alpha = int(pub["alpha"])
    assert pow(alpha, x, q) == y, "y should equal alpha^x mod q"

    print("Key generation correct")


def test_no_redundancy():
    priv1, pub1 = module_1.initialize_user("testuser")
    priv2, pub2 = module_1.initialize_user("testuser")
    assert priv1["x"] == priv2["x"], "Keys should not regenerate if they already exist"
    print("No Redundancy — keys not regenerated on second call")


def test_unique_per_user():
    module_1.initialize_user("alice")
    module_1.initialize_user("bob")
    alice_pub = json.load(open("keys/alice_public_key.json"))
    bob_pub = json.load(open("keys/bob_public_key.json"))
    assert alice_pub["y"] != bob_pub["y"], "Different users should have different keys"
    print("Different users get different keys")


test_key_generation()
test_no_redundancy()
test_unique_per_user()
