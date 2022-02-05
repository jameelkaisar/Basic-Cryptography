# Key Exchange
# Key Exchange algorithms are used to agree upon a shared secret between two communicating parties
# DH: Diffie Hellman
# We are using DH for Key Exchange


# Importing Libraries/Modules
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import time


# Class for Diffie Hellman Node
class Node():
    def __init__(self, parameters):
        self.parameters = parameters
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
        self.shared_key = None
        self.derived_key = None

    def get_public_key(self):
        return self.public_key

    def exchange_key(self, public_key, handshake_data=b""):
        self.shared_key = self.private_key.exchange(public_key)
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=handshake_data,
        )
        key = kdf.derive(self.shared_key)
        self.derived_key = key

    def get_derived_key(self):
        return self.derived_key


# Diffie Hellman
print("Diffie Hellman:")

# Starting Timer
start_time = time.time()

# Generating Parameters (takes time)
# You can reuse parameters
parameters = dh.generate_parameters(generator=2, key_size=2048)

# Creating Objects
node_falaen = Node(parameters)
node_fistaen = Node(parameters)

# Exchanging Public Keys
handshake_data = b"Handshake Data (You can skip this)"
public_key_falaen = node_falaen.get_public_key()
public_key_fistaen = node_fistaen.get_public_key()

node_falaen.exchange_key(public_key_fistaen, handshake_data)
node_fistaen.exchange_key(public_key_falaen, handshake_data)

# Getting Derived Keys
derived_key_falaen = node_falaen.get_derived_key()
derived_key_fistaen = node_fistaen.get_derived_key()
print(derived_key_falaen)
print(derived_key_fistaen)

# Stopping Timer
time_taken = time.time() - start_time
print(time_taken)
