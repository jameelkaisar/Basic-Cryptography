# Password Storage
# Password storage functions are used for storing passwords in a database
# We are using Scrypt key derivation function for password storage


# Importing Libraries/Modules
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey
import os


# Class for Password Storage
class PasswordStorage():
    def __init__(self):
        self.salt = os.urandom(16)

    def derive(self, password):
        kdf = Scrypt(
            salt=self.salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )
        key = kdf.derive(password)
        return key

    def verify(self, password, key):
        kdf = Scrypt(
            salt=self.salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )
        try:
            kdf.verify(password, key)
        except InvalidKey:
            return False
        return True


# Password Storage
print("Password Storage:")

# Creating Object
kdf = PasswordStorage()

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
