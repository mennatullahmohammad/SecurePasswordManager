import re
import sys
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

Base_URL = "http://cbc-ctf.westeurope.azurecontainer.io:5000"

session = requests.Session()
session.mount("http://", HTTPAdapter(max_retries=Retry(total=3, backoff_factor=0.3)))

# ── 1. Dump page HTML so we can find the real ciphertext ──────────────────────
print("Fetching page HTML...")
page = session.get(Base_URL + "/", timeout=15)
print("=" * 60)
print(page.text)
print("=" * 60)

# Find every lowercase hex string whose length is a multiple of 32
candidates = sorted(
    set(re.findall(r'[0-9a-f]{32,}', page.text)),
    key=len, reverse=True
)
print("\nCandidate hex strings (longest first):")
for c in candidates:
    if len(c) % 32 == 0:
        print(f"  {len(c):4d} chars  {c}")

# Use the longest valid-length one
CIPHERTEXT_HEX = next((c for c in candidates if len(c) % 32 == 0), None)
if not CIPHERTEXT_HEX:
    sys.exit("No hex ciphertext found in page — check HTML above and paste the real ciphertext into CIPHERTEXT_HEX manually.")

print(f"\nChosen ciphertext: {CIPHERTEXT_HEX}")
print(f"Length: {len(CIPHERTEXT_HEX)} hex chars = {len(CIPHERTEXT_HEX)//2} bytes = {len(CIPHERTEXT_HEX)//32} blocks\n")

# ── 2. Find the working oracle format ─────────────────────────────────────────
print("Probing oracle (trying every format)...")
USE_JSON = None
FIELD = None

for field in ["ciphertext", "ct", "hex", "ciphertext_hex", "cipher", "data"]:
    for use_json in [False, True]:
        kw = {"json" if use_json else "data": {field: CIPHERTEXT_HEX}}
        try:
            r = session.post(Base_URL + "/oracle", timeout=10, **kw)
            label = f"{'json' if use_json else 'form'}[{field!r}]"
            print(f"  {label:30s} {r.status_code}  {r.text[:80]}")
            if r.json().get("valid_padding") is True:
                USE_JSON, FIELD = use_json, field
                break
        except Exception as e:
            print(f"  error: {e}")
    if FIELD:
        break

if FIELD is None:
    sys.exit("No working oracle format found. Check the probe output above.")

print(f"\nWorking oracle: {'json' if USE_JSON else 'form-data'} field={FIELD!r}\n")

# ── 3. CBC Padding Oracle Attack ──────────────────────────────────────────────
def oracle(ct_hex):
    while True:
        try:
            kw = {"json" if USE_JSON else "data": {FIELD: ct_hex}}
            r = session.post(Base_URL + "/oracle", timeout=15, **kw)
            return r.json()["valid_padding"]
        except Exception as e:
            print(f"    [retry] {e}")

blocks = [CIPHERTEXT_HEX[i:i+32] for i in range(0, len(CIPHERTEXT_HEX), 32)]
IV           = blocks[0]
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
            # Send IV || crafted || target  (keeps length = original ciphertext)
            probe = IV + crafted.hex() + target_hex
            if oracle(probe):
                intermediate[byte_idx] = guess ^ padding_val
                pt = intermediate[byte_idx] ^ bytearray.fromhex(prev_hex)[byte_idx]
                print(f"  [{label}] byte {16 - byte_idx:2d}/16  "
                      f"pt=0x{pt:02x} ('{chr(pt) if 32 <= pt < 127 else '?'}')")
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
