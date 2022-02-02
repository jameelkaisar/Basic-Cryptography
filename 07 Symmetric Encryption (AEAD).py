# Symmetric Encryption
# Symmetric encryption is a type of encryption in which same key is used for encryption as well as decryption
# We are using AES for Symmetric Encryption
# AEAD: Authenticated Encryption with Associated Data
# We are using GCM for Authentication


# Importing Libraries/Modules
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import os


# Class for Encryption
class Encryptor():
    def __init__(self):
        self.key = AESGCM.generate_key(bit_length=256)

    def get_key(self):
        return self.key

    def encrypt_bytes(self, bytes_data, bytes_aad=None):
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.key)
        try:
            ciphertext = aesgcm.encrypt(nonce, bytes_data, bytes_aad)
        except OverflowError:
            raise OverflowError("bytes_data or bytes_aad is larger than ~2 GB.")
        fulltext = nonce + ciphertext
        return fulltext


# Class for Decryption
class Decryptor():
    def __init__(self, key):
        self.key = key

    def decrypt_bytes(self, fulltext, bytes_aad=None):
        nonce = fulltext[:12]
        bytes_data = fulltext[12:]
        aesgcm = AESGCM(self.key)
        try:
            plaintext = aesgcm.decrypt(nonce, bytes_data, bytes_aad)
        except InvalidTag:
            return None
        except OverflowError:
            raise OverflowError("fulltext or bytes_aad is larger than ~2 GB.")
        return plaintext


# Symmetric Encryption
print("Symmetric Encryption:")

# Creating Objects
encryptor = Encryptor()
key = encryptor.get_key()
decryptor = Decryptor(key)

# Encrypting Bytes
bytes_data = b"The quick brown fox jumps over the lazy dog"
fulltext = encryptor.encrypt_bytes(bytes_data)

# Decrypting Bytes
plaintext = decryptor.decrypt_bytes(fulltext)
print(plaintext)

# Encrypting Bytes with Associated Data
bytes_data = b"The quick brown fox jumps over the lazy dog"
bytes_aad = b"This data will be authenticated but not encrypted"
fulltext = encryptor.encrypt_bytes(bytes_data, bytes_aad)

# Decrypting Bytes with Associated Data
plaintext = decryptor.decrypt_bytes(fulltext, bytes_aad)
print(plaintext)

bytes_aad = b"This data has been altered"
plaintext = decryptor.decrypt_bytes(fulltext, bytes_aad)
print(plaintext)
