# Key Derivation
# Key derivation functions are used to generate cryptographically strong keys from passwords
# We are using PBKDF2 key derivation function


# Importing Libraries/Modules
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidKey
import os


# Class for Key Derivation
class KeyDerivation():
    def __init__(self):
        self.salt = os.urandom(16)

    def derive(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = kdf.derive(password)
        return key

    def verify(self, password, key):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        try:
            kdf.verify(password, key)
        except InvalidKey:
            return False
        return True


# Key Derivation
print("Key Derivation:")

# Creating Object
kdf = KeyDerivation()

# Deriving Key
password = b"My Name is Khan"
key = kdf.derive(password)
print(key)

# Verifying Password
result = kdf.verify(password, key)
print(result)
password = b"Wrong Password"
result = kdf.verify(password, key)
print(result)
