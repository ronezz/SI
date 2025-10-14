from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import  pubkeys


# Open private key 
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_ssh_private_key(
    key_file.read(),
    password=None,
    backend=default_backend()
    )

# Open public key 
with open("public_key.pub", "rb") as key_file:
    public_key = serialization.load_ssh_public_key(
    key_file.read(),
    backend=default_backend()
)

# Format userId to 5b
def adjust_userId(user_id):
    b = user_id.encode('utf-8')         
    b = b[:5]                           
    b = b.ljust(5, b'\x00')             
    return b

def _bytes5_to_str(b5):
    return b5.rstrip(b'\x00').decode('utf-8', errors='ignore')

# Find user public key
def find_pubKey(user_id):
    public_key= pubkeys.pubkey_dict.get(user_id)
    
    if public_key is not None:
        return serialization.load_ssh_public_key(
                ('ssh-rsa ' + public_key).encode('ascii'),
                backend=default_backend())
    else:
        print("Public key not found")
    
    return public_key 


# AESCG Functions
def aesgcm_encryption(key, data):
    aesgcm = AESGCM(key)
    nonce = key
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return ciphertext


def aescgm_descryption(key, ciphertext):
    aesgcm = AESGCM(key)
    nonce = key
    return aesgcm.decrypt(nonce, ciphertext, None)

# RSA Functions
def rsa_encryption(public_key, message):
    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)
    )
    return encrypted


def rsa_decryption(encrypted):
    original_message = private_key.decrypt(
    encrypted,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None)
    )
    return original_message

# Hybrid Encryption/Decryption
def hybrid_encryption(public_key, data):
    key = AESGCM.generate_key(bit_length=128)
    aescgm_cipher = aesgcm_encryption(key, data)
    rsa_cipher = rsa_encryption(public_key, key)
    return rsa_cipher + aescgm_cipher

def hybrid_decryption(ciphertext):
    key_length = private_key.key_size // 8

    cipher_key = ciphertext[:key_length]
    cipher_data = ciphertext[key_length:]

    key = rsa_decryption(cipher_key)
    data = aescgm_descryption(key, cipher_data)

    return data

# Onion Functions

# Build
def nest_hybrid_encryption(path, data, anonymous):
    sender = path[0]
    recipient = path[-1]
    
    # Check if we want to send the message anonymously
    sender_field = "none" if anonymous else sender

    final_content = adjust_userId("end") + adjust_userId(sender_field) + data
    ciphertext = hybrid_encryption(find_pubKey(recipient), final_content)
    for index in range(len(path) - 2, -1, -1):
        current_hop = path[index]
        next_hop = path[index + 1]
        payload_for_hop = adjust_userId(next_hop) + ciphertext
        ciphertext = hybrid_encryption(find_pubKey(current_hop), payload_for_hop)

    return ciphertext

# Peel
def decode_and_relay(ciphertext):
    
    payload = hybrid_decryption(ciphertext)
    next_hop = payload[:5]
    rest = payload[5:]

    nh = _bytes5_to_str(next_hop).lower()
    if nh != "end":
        return ("forward", _bytes5_to_str(next_hop), rest)
    else:
        sender = _bytes5_to_str(rest[:5])
        message = rest[5:]
        return ("deliver", sender, message)