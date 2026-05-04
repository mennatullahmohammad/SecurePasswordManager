import re
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

Base_URL = "http://cbc-ctf.westeurope.azurecontainer.io:5000"

session = requests.Session()
session.mount("http://", HTTPAdapter(max_retries=Retry(total=5, backoff_factor=0.3)))

# Fetch the page and dump everything useful for debugging
print("Fetching challenge page...")
page = session.get(Base_URL + "/", timeout=15)

all_hex = re.findall(r'[0-9a-fA-F]{32,}', page.text)
print(f"\nAll hex strings on page ({len(all_hex)} found):")
for h in all_hex:
    print(f"  len={len(h):4d}  {h[:80]}{'...' if len(h) > 80 else ''}")

print("\n--- Page HTML (first 2000 chars) ---")
print(page.text[:2000])
print("--- end ---\n")

# Pick the longest lowercase-only hex string whose length is a multiple of 32
candidates = [h for h in re.findall(r'[0-9a-f]{32,}', page.text) if len(h) % 32 == 0]
if not candidates:
    print("No valid ciphertext candidates. Check HTML dump above.")
    exit(1)
CIPHERTEXT_HEX = max(candidates, key=len)
print(f"Using ciphertext ({len(CIPHERTEXT_HEX)} hex chars = {len(CIPHERTEXT_HEX)//2} bytes): {CIPHERTEXT_HEX}")

blocks = [CIPHERTEXT_HEX[i:i+32] for i in range(0, len(CIPHERTEXT_HEX), 32)]
IV = blocks[0]
cipher_blocks = blocks[1:]
print(f"IV + {len(cipher_blocks)} cipher block(s)")

def oracle(ciphertext_hex):
    while True:
        try:
            resp = session.post(
                Base_URL + "/oracle",
                data={"ciphertext": ciphertext_hex},
                timeout=15
            )
            return resp.json()["valid_padding"]
        except Exception as e:
            print(f"  [retry] {e}")

# Sanity check
print("\nSanity check: original ciphertext (expect True)...")
_resp = session.post(Base_URL + "/oracle", data={"ciphertext": CIPHERTEXT_HEX}, timeout=15)
print(f"  Status: {_resp.status_code}  Response: {_resp.text}")
assert _resp.json().get("valid_padding"), "Oracle failed — check the HTML dump and response above"

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
                pt_byte = intermediate[byte_idx] ^ bytearray.fromhex(prev_hex)[byte_idx]
                print(f"  [{label}] byte {16-byte_idx:2d}/16 -> 0x{pt_byte:02x} ('{chr(pt_byte) if 32 <= pt_byte < 127 else '?'}')")
                break

    prev = bytearray.fromhex(prev_hex)
    return bytearray(intermediate[i] ^ prev[i] for i in range(16))

plaintext = bytearray()
prev = IV
for i, block in enumerate(cipher_blocks):
    print(f"\nDecrypting block {i+1}/{len(cipher_blocks)}...")
    plaintext += decrypt_block(prev, block, f"B{i+1}")
    prev = block

pad_len = plaintext[-1]
if 1 <= pad_len <= 16:
    plaintext = plaintext[:-pad_len]

print("\nFlag:", plaintext.decode("utf-8", errors="replace"))
