from Crypto.Util.number import getPrime, isPrime, inverse
from Crypto.Random.random import randint
from math import gcd
import json


p, q, alpha = None, None, None


def save_to_json(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f)


def load_json(filename):
    with open(filename, "r") as f:
        return json.load(f)


def generate_params(bits=512):
    while True:
        p = getPrime(bits - 1)
        q = 2*p + 1
        if (isPrime(q)):
            break

    while True:
        alpha = randint(2, q - 2)
        if pow(alpha, 2, q) != 1 and pow(alpha, p, q) != 1:  # must ensure that number is actually a large primitive root with a large cycle and not having a small 2 step cycle for security reasons
            break

    return p, q, alpha


def generate_and_store():
    global p, q, alpha
    p, q, alpha = generate_params()
    save_to_json("params.json", {"p": str(p), "q": str(q), "alpha": str(alpha)})


def load_params():
    global p, q, alpha
    data = load_json("params.json")
    p = int(data["p"])
    q = int(data["q"])
    alpha = int(data["alpha"])


if __name__ == "__main__":
    generate_and_store()
    print("Parameters generated and stored.")
