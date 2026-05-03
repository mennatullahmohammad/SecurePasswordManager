import os
import json
import base64
import hashlib
import config
import module_1
import module_3
from Crypto.Cipher import AES
VAULT_DIR = "vaults"
def derive_key(master_password: str) -> bytes:
    # Use SHA-256 to derive a 32-byte key from the master password
    return hashlib.sha256(master_password.encode()).digest()

def _vault_path(username: str) -> str:
    return os.path.join(VAULT_DIR, f"{username}_vault.json")

def _load_vault(username: str) -> dict:
    path = _vault_path(username)
    if not os.path.exists(path):
        raise FileNotFoundError(f"No vault found for '{username}'. Run initialize first.")
    with open(path, "r") as f:
        return json.load(f)
    
def _save_vault(username: str, vault: dict):
    os.makedirs(VAULT_DIR, exist_ok=True)
    with open(_vault_path(username), "w") as f:
        json.dump(vault, f, indent=2)

def encrypt_credentials(credentials: list, key: bytes) -> str:
    plaintext = json.dumps(credentials).encode()
    nonce = os.urandom(16)
    cipher = AES.new(key, AES.MODE_GCM)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    bundle = nonce + tag + ciphertext        
    return base64.b64encode(bundle).decode()

def decrypt_credentials(encrypted_data: str, key: bytes) -> list:
    try:
        bundle = base64.b64decode(encrypted_data)
        nonce = bundle[:16]
        tag = bundle[16:32]
        ciphertext = bundle[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return json.loads(plaintext.decode())
    except (ValueError, KeyError):
        raise ValueError("Decryption failed. Invalid encrypted data or key.")
    
def _sign_vault(encrypted_vault: str, private_key: dict, public_key: dict) -> dict:
    q=int(public_key["q"])
    alpha=int(public_key["alpha"])
    vault_hash = module_3.hash_vault(encrypted_vault)
    r, s = module_3.sign(vault_hash, private_key["x"],q,alpha)
    return {"r": str(r), "s": str(s)}

def _verify_vault(encrypted_vault: str, signature: dict, public_key: dict) -> bool:
    if not signature or "r" not in signature or "s" not in signature:
        return False
    q=int(public_key["q"])
    alpha=int(public_key["alpha"])
    y=int(public_key["y"])
    vault_hash = module_3.hash_vault(encrypted_vault)
    r = int(signature["r"])
    s = int(signature["s"])
    return module_3.verify(r, s, vault_hash, y, alpha, q)

def initialize_vault(username: str, master_password: str):
      private_key, public_key = module_1.initialize_user(username)
      key=derive_key(master_password)
      encrypted = encrypt_credentials([], key)
      signature = _sign_vault(encrypted, private_key, public_key)
      vault = {
            "username": username,
            "encrypted_vault": encrypted,
            "signature": signature
        }   
      _save_vault(username, vault)
      print(f"Vault initialized for '{username}'")

def add_credential(username: str, master_password: str,site: str, site_username: str, site_password: str):
    private_key, public_key = module_1.initialize_user(username)
    vault = _load_vault(username)
    if not _verify_vault(vault["encrypted_vault"], vault["signature"], public_key):
        raise PermissionError("Vault signature invalid! File may have been tampered with.")
    key = derive_key(master_password)
    credentials = decrypt_credentials(vault["encrypted_vault"], key)
    for c in credentials:
        if c["site"] == site:
            raise ValueError(f"Entry for '{site}' already exists. Use update instead.")

    credentials.append({
        "site": site,
        "username": site_username,
        "password": site_password
    })
    vault["encrypted_vault"] = encrypt_credentials(credentials, key)
    vault["signature"] = _sign_vault(vault["encrypted_vault"], private_key, public_key)
    _save_vault(username, vault)
    print(f"Credential for '{site}' added successfully.")

def get_credentials(username: str, master_password: str, site: str = None) -> list:
    private_key, public_key = module_1.initialize_user(username)
    vault = _load_vault(username)
    if not _verify_vault(vault["encrypted_vault"], vault["signature"], public_key):
        raise PermissionError("Invalid signature")
    key = derive_key(master_password)
    credentials = decrypt_credentials(vault["encrypted_vault"], key)
    if site:
        for c in credentials:
            if c["site"] == site:
                return [c]
        raise ValueError(f"No entry found for '{site}'.")
    return credentials

def update_credential(username: str, master_password: str, site: str, new_username: str = None, new_password: str = None):
    private_key, public_key = module_1.initialize_user(username)
    vault = _load_vault(username)
    if not _verify_vault(vault["encrypted_vault"], vault["signature"], public_key):
        raise PermissionError("Invalid signature")
    key = derive_key(master_password)
    credentials = decrypt_credentials(vault["encrypted_vault"], key)
    found=False
    for c in credentials:
        if c["site"] == site:
            found=True
            if new_username is not None:
                c["username"] = new_username
            if new_password is not None:
                c["password"] = new_password
            break
    if not found:
        raise ValueError(f"No entry found for '{site}'.")
    vault["encrypted_vault"] = encrypt_credentials(credentials, key)
    vault["signature"] = _sign_vault(vault["encrypted_vault"], private_key, public_key)
    _save_vault(username, vault)
    print(f"Credential for '{site}' updated successfully.")