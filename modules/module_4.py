import os
import sys
import base64
import hashlib
import config

from Crypto.Cipher import AES
from Crypto.Random.random import randint
from module_3 import sign,verify,hash_vault

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


