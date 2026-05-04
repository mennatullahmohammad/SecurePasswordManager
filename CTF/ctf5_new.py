import re
import sys
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

Base_URL = "http://cbc-ctf.westeurope.azurecontainer.io:5000"

session = requests.Session()
session.mount("http://", HTTPAdapter(max_retries=Retry(total=3, backoff_factor=0.3)))

print("Fetching page HTML...")
page = session.get(Base_URL + "/", timeout=15)

candidates = sorted(
    set(re.findall(r'[0-9a-f]{32,}', page.text)),
    key=len, reverse=True
)
CIPHERTEXT_HEX = next((c for c in candidates if len(c) % 32 == 0), None)
if not CIPHERTEXT_HEX:
    sys.exit("No hex ciphertext found in page.")

print(f"Ciphertext: {CIPHERTEXT_HEX} ({len(CIPHERTEXT_HEX)//32} blocks)\n")

print("Probing oracle format...")
USE_JSON = None
FIELD = None

for field in ["ciphertext", "ct", "hex", "ciphertext_hex", "cipher", "data"]:
    for use_json in [False, True]:
        kw = {"json" if use_json else "data": {field: CIPHERTEXT_HEX}}
        try:
            r = session.post(Base_URL + "/oracle", timeout=10, **kw)
            if r.json().get("valid_padding") is True:
                USE_JSON, FIELD = use_json, field
                break
        except Exception:
            pass
    if FIELD:
        break

if FIELD is None:
    sys.exit("No working oracle format found.")

print(f"Working oracle: {'json' if USE_JSON else 'form-data'} field={FIELD!r}\n")


def oracle(ct_hex):
    while True:
        try:
            kw = {"json" if USE_JSON else "data": {FIELD: ct_hex}}
            r = session.post(Base_URL + "/oracle", timeout=15, **kw)
            return r.json()["valid_padding"]
        except Exception as e:
            print(f"    [retry] {e}")


blocks = [CIPHERTEXT_HEX[i:i+32] for i in range(0, len(CIPHERTEXT_HEX), 32)]
IV = blocks[0]
cipher_blocks = blocks[1:]


def decrypt_block(prev_hex, target_hex, label=""):
    intermediate = bytearray(16)
    for byte_idx in range(15, -1, -1):
        padding_val = 16 - byte_idx
        crafted = bytearray(16)
        for k in range(byte_idx + 1, 16):
            crafted[k] = intermediate[k] ^ padding_val

        for guess in range(256):
            crafted[byte_idx] = guess
            if oracle(IV + crafted.hex() + target_hex):
                intermediate[byte_idx] = guess ^ padding_val
                pt = intermediate[byte_idx] ^ bytearray.fromhex(prev_hex)[byte_idx]
                print(f"  [{label}] byte {16 - byte_idx:2d}/16  pt=0x{pt:02x} ('{chr(pt) if 32 <= pt < 127 else '?'}')")
                break

    prev = bytearray.fromhex(prev_hex)
    return bytearray(intermediate[i] ^ prev[i] for i in range(16))


plaintext = bytearray()
prev = IV
for i, blk in enumerate(cipher_blocks):
    print(f"\nDecrypting block {i + 1}/{len(cipher_blocks)} ...")
    plaintext += decrypt_block(prev, blk, f"B{i+1}")
    prev = blk

pad_len = plaintext[-1]
if 1 <= pad_len <= 16:
    plaintext = plaintext[:-pad_len]

print("\n>>> FLAG:", plaintext.decode("utf-8", errors="replace"))
