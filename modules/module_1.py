import os
import config
from Crypto.Random.random import randint

config.load_params()


def is_valid_file(path):
    return os.path.exists(path) and os.path.getsize(path) > 0


def key_generation(username: str):

    priv_path = f"keys/{username}_private_key.json"
    pub_path = f"keys/{username}_public_key.json"

    if is_valid_file(priv_path) and is_valid_file(pub_path):
        return config.load_json(priv_path), config.load_json(pub_path)

    x = randint(2, config.q - 2)
    y = pow(config.alpha, x, config.q)

    private_key = {
        "username": username,
        "x": str(x)}
    public_key = {
        "username": username,
        "y": str(y),
        "q": str(config.q),
        "alpha": str(config.alpha)}

    config.save_to_json(priv_path, private_key)
    config.save_to_json(pub_path, public_key)

    return private_key, public_key


def initialize_user(username):
    return key_generation(username)
