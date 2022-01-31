# Padding
# Padding is used in block ciphers for making the input data size a multiple of block size
# We are using PKCS7 padding


# Importing Libraries/Modules
from cryptography.hazmat.primitives import padding


# Class for Padding
class Padder():
    def __init__(self, block_size=128):
        self.padder = padding.PKCS7(block_size).padder()

    def update(self, bytes_data):
        padded_data = self.padder.update(bytes_data)
        return padded_data

    def finalize(self):
        padded_data = self.padder.finalize()
        return padded_data


# Class for Unpadding
class Unpadder():
    def __init__(self, block_size=128):
        self.unpadder = padding.PKCS7(block_size).unpadder()

    def update(self, bytes_data):
        unpadded_data = self.unpadder.update(bytes_data)
        return unpadded_data

    def finalize(self):
        unpadded_data = self.unpadder.finalize()
        return unpadded_data


# Padding
print("Padding:")

# Creating Object
padder = Padder()

# Adding Data
padded_data_1 = padder.update(b"This is some data which needs padding.")
print(padded_data_1)

# Adding More Data
padded_data_2 = padder.update(b"More data.")
print(padded_data_2)

# Adding More Data
padded_data_3 = padder.update(b"Final bytes.")
print(padded_data_3)

# Finalizing Padding
padded_data_4 = padder.finalize()
print(padded_data_4)

# Complete Padded Data
padded_data = padded_data_1 + padded_data_2 + padded_data_3 + padded_data_4
print(padded_data)


# Unpadding
print("Unpadding:")

# Creating Object
unpadder = Unpadder()

# Adding Data
unpadded_data_1 = unpadder.update(padded_data_1)
print(unpadded_data_1)

# Adding More Data
unpadded_data_2 = unpadder.update(padded_data_2)
print(unpadded_data_2)

# Adding More Data
unpadded_data_3 = unpadder.update(padded_data_3)
print(unpadded_data_3)

# Adding More Data
unpadded_data_4 = unpadder.update(padded_data_4)
print(unpadded_data_4)

# Finalizing Padding
unpadded_data_5 = unpadder.finalize()
print(unpadded_data_5)

# Complete Padded Data
unpadded_data = unpadded_data_1 + unpadded_data_2 + unpadded_data_3 + unpadded_data_4 + unpadded_data_5
print(unpadded_data)
