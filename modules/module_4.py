import os
import json
import base64
import hashlib
import config

from Crypto.Cipher import AES
from Crypto.Random.random import randint
from module_3 import sign,verify,hash_vault
import module_2

config.load_params()

TRANSFER_DIR = "transfers"

################## DH ###################

def select_keys(q, alpha):
    privKey = randint(2, q-2) #select a random number between 2 and q-2 to be private key 'X'
    pubKey = pow(alpha, privKey, q) # public key=((alpha)^PrivateKey)mod q 'Y'
    return privKey,pubKey

def compute_key(otherPubKey, myPrivKey,q):
    K=pow(otherPubKey,myPrivKey,q)
    return K

def hash_key(key):
    return hashlib.sha256(str(key).encode()).digest()

################## AES-GCM ###################
# bundle: nonce(16)+tag(16)+ciphertext 

def AES_encrypt(plaintext: bytes,key: bytes)->str:
    cipher= AES.new(key,AES.MODE_GCM)
    ciphertext,tag=cipher.encrypt_and_digest(plaintext)
    bundle=cipher.nonce+tag+ciphertext
    return base64.b64encode(bundle).decode()

def AES_decrypt(bundle: str,key: bytes)->bytes:
    raw = base64.b64decode(bundle)
    nonce=raw[:16]
    tag=raw[16:32]
    ciphertext=raw[32:]
    cipher=AES.new(key,AES.MODE_GCM,nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext,tag)


def _transfer_path(sender:str, receiver:str)->str:
    return os.path.join(TRANSFER_DIR, f"{sender}_to_{receiver}.json")


def export_vault(sender:str,receiver:str,master_password:str):
    sender=sender.lower()
    receiver=receiver.lower()
    priv_path=f"keys/{sender}_private_key.json"
    sender_public_path=f"keys/{sender}_public_key.json"
    receiver_public_path=f"keys/{receiver}_public_key.json"

    if not os.path.exists(priv_path):
        raise FileNotFoundError(f"Keys not found for '{sender}'. Initialize your vault first.")
    if not os.path.exists(receiver_public_path):
        raise FileNotFoundError(f"Keys not found for '{receiver}'.  Recipient must initialize their vault first.")


    sender_priv=config.load_json(priv_path)
    sender_public=config.load_json(sender_public_path)
    receiver_public=config.load_json(receiver_public_path)

    vault_path=f"vaults/{sender}_vault.json" 
    if not os.path.exists(vault_path):
        raise FileNotFoundError(f"No vault found for '{sender}'.")
    with open(vault_path,"r") as f:
        vault=json.load(f)
    
    q=int(sender_public["q"])
    alpha=int(sender_public["alpha"])
    x_sender=int(sender_priv["x"])
    y_sender=int(sender_public["y"])
    y_receiver=int(receiver_public["y"])

    sig=vault.get("signature", {})
    if not sig or "r" not in sig or "s" not in sig:
        raise PermissionError("Vault has no valid signature.")
    if not verify(int(sig["r"]),int(sig["s"]),hash_vault(vault["encrypted_vault"]),y_sender,alpha,q):
        raise PermissionError("Vault signature invalid! Vault may have been tampered with.")
    
    dh_shared=compute_key(y_receiver,x_sender,q)
    session_key=hash_key(dh_shared)

    master_key=hashlib.sha256(master_password.encode()).digest()
    credentials= module_2.decrypt_credentials(vault["encrypted_vault"],master_key)
    encrypted_export=module_2.encrypt_credentials(credentials,session_key)

    r,s=sign(hash_vault(encrypted_export),x_sender,q,alpha)
    os.makedirs(TRANSFER_DIR,exist_ok=True)
    transfer={
        "sender":sender,
        "recipient":receiver,
        "encrypted_vault":encrypted_export,
        "signature":{"r":str(r),"s":str(s)}
    }
    path=_transfer_path(sender,receiver)
    with open(path,"w") as f:
        json.dump(transfer,f,indent=2)
    
    print(f"Vault exported successfully to '{receiver}'.")
    print(f"Transfer file: {path}")

def import_vault(receiver:str,sender:str,master_password:str):
    receiver=receiver.lower()
    sender=sender.lower()
    priv_path=f"keys/{receiver}_private_key.json"
    sender_public_path=f"keys/{sender}_public_key.json"

    if not os.path.exists(priv_path):
        raise FileNotFoundError(f"Keys not found for '{receiver}'. Initialize your vault first.")
    if not os.path.exists(sender_public_path):
        raise FileNotFoundError(f"Keys not found for '{sender}'.") 
    
    receiver_priv=config.load_json(priv_path) #just reads the file in the path
    sender_public=config.load_json(sender_public_path)

    path=_transfer_path(sender,receiver)
    if not os.path.exists(path):
        raise FileNotFoundError(f"No transfer file found from '{sender}' to '{receiver}'.")
    with open(path,"r") as f:
        transfer=json.load(f)
    
    q=int(sender_public["q"])
    alpha=int(sender_public["alpha"])
    y_sender=int(sender_public["y"])
    x_receiver=int(receiver_priv["x"])

    sig=transfer.get("signature",{})
    if not sig or "r" not in sig or "s" not in sig:
        raise PermissionError("Transfer file has no valid signature.")
    if not  verify(int(sig["r"]),int(sig["s"]),hash_vault(transfer["encrypted_vault"]),y_sender,alpha,q):
        raise PermissionError("Transfer signature invalid! Data may have been tampered with.")
    
    dh_shared=compute_key(y_sender,x_receiver,q)
    select_key=hash_key(dh_shared)

    credentials=module_2.decrypt_credentials(transfer["encrypted_vault"],select_key)
    vault_path=f"vaults/{receiver}_vault.json"
    if not os.path.exists(vault_path):
        raise FileNotFoundError(f"No vault found for '{receiver}'. Initialize your vault first.")
    imported=0
    skipped=0

    for cred in credentials:
        try:
            module_2.add_credential(
                receiver,
                master_password,
                cred["site"],cred["username"],cred["password"]
            )
            imported+=1
        except ValueError:
            skipped+=1
    print(f"Import complete: {imported} credential(s) imported, {skipped} skipped (already exist).") 
    os.remove(path)
    print("Transfer file cleaned up.")
    

    



