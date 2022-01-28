# Random
# It is important to generate random keys and numbers which are cryptographically secure
# We are using os.urandom() for getting random bytes


# Importing Libraries/Modules
import os


# Class for Generating Random Keys and Numbers
class Random():
    def key(self, length):
        random_key = os.urandom(length)
        return random_key

    def number(self, length):
        random_number = int.from_bytes(os.urandom(length), byteorder="big")
        return random_number


# Random
print("Random:")

# Creating Object
generator = Random()

# Generating Key
key = generator.key(32)
print(key)

# Generating Number
number = generator.number(32)
print(number)
