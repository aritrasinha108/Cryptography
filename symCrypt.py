import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
key=os.urandom(32)
iv=os.urandom(16)
backend=default_backend()
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)



def add_padding(str):
    # to add padding
    if(len(str) % 32) != 0:
        r = len(str) % 32
        str += " " * (32-r)
    return str


def no_padding(s):
    # to remove padding
    return " ".join(s.split())


def enc(message):
    encryptor = cipher.encryptor()
    ct = encryptor.update(message.encode('ascii')) + encryptor.finalize()
    return key, ct, iv



def dec(key, ct , iv):
    decryptor = cipher.decryptor()
    message = decryptor.update(ct) + decryptor.finalize()
    return message.decode('ascii')


# INPUT FROM THE USER
message = input("Enter the message to be sent: ")
padded_message = add_padding(message)


key, ct, iv = enc(padded_message)
decrypt_message = dec(key, ct, iv)

# Remove unnecessary padding
final_message = no_padding(decrypt_message)
# c=b""
# c=ct
print("The encrypted message is: ", ct)
print("The decoded message is: ", final_message)
print("key:", key)
