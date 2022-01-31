# Symmetric Encryption
# Symmetric encryption is a type of encryption in which same key is used for encryption as well as decryption
# We are using AES for Symmetric Encryption
# No Authentication


# Importing Libraries/Modules
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives import padding
import os


# Class for Encryption
class Encryptor():
    def __init__(self):
        self.key = os.urandom(32)

    def get_key(self):
        return self.key

    def encrypt_bytes(self, bytes_data):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(bytes_data)
        padded_data += padder.finalize()
        ciphertext = encryptor.update(padded_data)
        ciphertext += encryptor.finalize()
        fulltext = iv + ciphertext
        return fulltext

    def __file_chunks(self, file_object, chunk_size=65536):
        while True:
            data_chunk = file_object.read(chunk_size)
            if not data_chunk:
                break
            yield data_chunk

    def encrypt_file(self, plain_file_path, encrypted_file_path):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(iv)
            with open(plain_file_path, "rb") as plain_file:
                for data_chunk in self.__file_chunks(plain_file):
                    padded_data = padder.update(data_chunk)
                    ciphertext = encryptor.update(padded_data)
                    encrypted_file.write(ciphertext)
                padded_data = padder.finalize()
                ciphertext = encryptor.update(padded_data)
                ciphertext += encryptor.finalize()
                encrypted_file.write(ciphertext)


# Class for Decryption
class Decryptor():
    def __init__(self, key):
        self.key = key

    def decrypt_bytes(self, fulltext):
        iv = fulltext[:16]
        ciphertext = fulltext[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext)
        plaintext += decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(plaintext)
        unpadded_data += unpadder.finalize()
        return unpadded_data

    def __file_chunks(self, file_object, chunk_size=65536):
        while True:
            data_chunk = file_object.read(chunk_size)
            if not data_chunk:
                break
            yield data_chunk

    def decrypt_file(self, encrypted_file_path, decrypted_file_path):
        with open(encrypted_file_path, "rb") as encrypted_file:
            iv = encrypted_file.read(16)
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()
            with open(decrypted_file_path, "wb") as decrypted_file:
                for data_chunk in self.__file_chunks(encrypted_file):
                    plaintext = decryptor.update(data_chunk)
                    unpadded_data = unpadder.update(plaintext)
                    decrypted_file.write(unpadded_data)
                plaintext = decryptor.finalize()
                unpadded_data = unpadder.update(plaintext)
                unpadded_data += unpadder.finalize()
                decrypted_file.write(unpadded_data)


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

# Creating a Sample File
plain_file_path = "Sample File.txt"
with open(plain_file_path, "w") as file:
    file.write("The quick brown fox jumps over the lazy dog")

# Encrypting File
encrypted_file_path = "Sample File (Encrypted).txt"
encryptor.encrypt_file(plain_file_path, encrypted_file_path)

# Decrypting File
decrypted_file_path = "Sample File (Decrypted).txt"
decryptor.decrypt_file(encrypted_file_path, decrypted_file_path)
