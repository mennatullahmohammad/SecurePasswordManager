import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

Base_URL = "http://cbc-ctf.westeurope.azurecontainer.io:5000"
CIPHERTEXT_HEX = "b248f0e8f4e3548b995d2215f54b72bd5d3b211b522b7a5ea25c5763e7425447e440e4d85933807e1385d11cd1959975"

blocks = [CIPHERTEXT_HEX[i:i+32] for i in range(0, len(CIPHERTEXT_HEX), 32)]
IV, C1, C2 = blocks[0], blocks[1], blocks[2]

session = requests.Session()
session.mount("http://", HTTPAdapter(max_retries=Retry(total=5, backoff_factor=0.3)))

def oracle(ciphertext_hex):
    while True:
        try:
            resp = session.post(
                Base_URL + "/oracle",
                json={"ciphertext": ciphertext_hex},
                timeout=15
            )
            return resp.json()["valid_padding"]
        except Exception:
            pass

def decrypt_block(prev_hex, target_hex, label=""):
    intermediate = bytearray(16)
    for byte_idx in range(15, -1, -1):
        padding_val = 16 - byte_idx
        crafted = bytearray(16)
        for k in range(byte_idx + 1, 16):
            crafted[k] = intermediate[k] ^ padding_val

        for guess in range(256):
            crafted[byte_idx] = guess
            if oracle(crafted.hex() + target_hex):
                intermediate[byte_idx] = guess ^ padding_val
                plaintext_byte = intermediate[byte_idx] ^ bytearray.fromhex(prev_hex)[byte_idx]
                print(f"  [{label}] byte {16 - byte_idx:2d}/16 -> 0x{intermediate[byte_idx]:02x} ('{chr(plaintext_byte) if 32 <= plaintext_byte < 127 else '?'}')")
                break

    prev = bytearray.fromhex(prev_hex)
    return bytearray(intermediate[i] ^ prev[i] for i in range(16))

print("Decrypting block 1...")
p1 = decrypt_block(IV, C1, "B1")
print("Decrypting block 2...")
p2 = decrypt_block(C1, C2, "B2")

plaintext = p1 + p2
pad_len = plaintext[-1]
if 1 <= pad_len <= 16:
    plaintext = plaintext[:-pad_len]

print("\nFlag:", plaintext.decode("utf-8", errors="replace"))
