import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
key=os.urandom(32)
iv=os.urandom(16)
backend=default_backend()


def add_padding(str):
    # to add padding
    if(len(str)%32)!=0:
        r=len(str)%32
        str+=" "*(32-r)
    return str


def no_padding(s):
    # to remove padding
    return " ".join(s.split())


def encrypt(plaintext: str):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),backend=backend)
    encryptor = cipher.encryptor
    cipherText = encryptor.update(plaintext) + encryptor.finalize()
    return key, cipherText, iv


def decrypt(key, cipherText , iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    message = decryptor.update() + decryptor.finalize()
    return message.decode()


# INPUT FROM THE USER
message = input("Enter the message to be sent: ")
padded_message = add_padding(message)
# converting to bytes
byte_string = padded_message.encode()
key, cipherText, iv = encrypt(byte_string)
decrypt_message = decrypt(key, cipherText, iv)
decoded_message= decrypt_message
# Remove unnecessary padding
final_message = no_padding(decoded_message)
print("The encrypted message is: " + cipherText)
print("The decoded message is: " + final_message)
