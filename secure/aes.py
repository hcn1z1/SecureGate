from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64


def pad(text):
    # AES block size is 16 bytes
    padding_len = AES.block_size - len(text) % AES.block_size
    padding = chr(padding_len) * padding_len
    return text + padding


def unpad(text):
    padding_len = ord(text[-1])
    return text[:-padding_len]

# Encrypt function
def encrypt(plaintext, key):
    plaintext = pad(plaintext)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(iv + ciphertext).decode('utf-8')

# Decrypt function
def decrypt(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:AES.block_size]
    actual_ciphertext = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(actual_ciphertext).decode('utf-8')
    return unpad(plaintext)

