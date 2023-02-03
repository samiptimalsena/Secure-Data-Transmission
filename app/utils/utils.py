from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def encrypt_AES(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(pad(plaintext, AES.block_size))
    return (cipher.nonce, tag, ciphertext)

def decrypt_AES(key, nonce, tag, ciphertext):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    try:
        cipher.verify(tag)
        return plaintext
    except ValueError:
        return None

def generate_RSA_key(n=2048):
    private_key = RSA.generate(n)
    public_key = private_key.publickey()
    # return bytes(str(private_key), encoding="utf-8"), bytes(str(public_key), encoding="utf-8")
    return private_key.export_key(), public_key.export_key()

def encrypt_RSA(public_key, data):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)

def decrypt_RSA(private_key, encrypted_data):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_data)

def load_RSA_key(path):
    with open(path) as f:
        key = RSA.import_key(f.read())
    return key

def save_RSA_key(key, path):
    with open(path, "wb") as f:
        f.write(key)

def load_AES_key(path):
    with open(path, "rb") as f:
        key = f.read()
        return key

def save_AES_key(key, path):
    with open(path, "wb") as f:
        f.write(key)
