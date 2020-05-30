import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


mt = ct = msg = m = y = civ = ck = private_key = public_key = None

backend = default_backend()
key = os.urandom(32)
iv = os.urandom(16)


class Communicate:

    def __init__(self, name):
        self.name = name

    global public_key, private_key

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    public_key = private_key.public_key()

    def privkey(self):
        self.privkey = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())

        return self.privkey

    # class method that returns serialized public key
    def pubkey(self):
        self.pubkey = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        return self.pubkey

    def sign(self, message):
        self.signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256())
        return self.signature

    def verify(self, signature, message):
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256())
        print("\nDIGITAL SIGNATURE VERIFICATION SUCCESSFUL. ENCRYPTED KEY RECEIVED IS AUTHENTIC.")

    def encryption(self, message):
        self.ciphertext = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return self.ciphertext

    def decryption(self, ciphertext):
        self.plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return self.plaintext


Alice = Communicate("Alice")
Bob = Communicate("Bob")


def one(a):
    x = a.privkey()
    y = a.pubkey()
    print("\nPrivate Key of ", a.name, " is ", x)
    print("\n Public Key of ", a.name, " is ", y)


def sen(a, b):
    global ck, civ, y, m, key, iv
    print("\nSessional Key generated is : \n", key)
    print("\nSessional IV generated is : \n", iv)
    ck = b.encryption(key)
    civ = b.encryption(iv)
    print("\nEncrypted sessional Key is : \n", ck)
    print("\nEncrypted sessional IV  is : \n", civ)
    m = (input("\n\nEnter Signature of Sender: "))
    m = m.encode()
    y = a.sign(m)
    print("\nDigital Signature of sender generated as:\n",y)
    print("\nEncrypted Key along with Digital Signature sent.")


def rec(a, b):
    global k, i, y, m
    k = b.decryption(ck)
    i = b.decryption(civ)
    print("\nDecrypted Sessional Key received is : \n", k)
    print("\nDecrypted Sessional Key received is : \n", i)

    a.verify(y, m)


def send(a,b):
    global msg, m, ct, y
    msg = (input("\nEnter message sender wants to send is: "))
    msg = msg.encode()
    ct = b.encryption(msg)
    m = (input("\n\nEnter Signature of Sender: "))
    m = m.encode()
    y = a.sign(m)
    print("\nDigital Signature of sender generated as:\n", y)
    print("Encrypted message is: ", ct)


def receive(a, b):
    global m, y, mt
    mt = b.decryption(ct)
    mt = mt.decode()
    a.verify(y, m)
    print("\nThe decrypted message from ", a.name, " to ", b.name, " is:\n", mt)


def main():
    x = "y"

    while x is "y" or x is "Y":
        print("\nMAIN MENU:\n")
        print("1.Generate Alice's pair of public and private keys")
        print("2.Generate Bob's pair of public and private keys")
        print("3.Send a symmetric key from Alice to Bob")
        print("4.Recieve the key")
        print("5.Send a message from alice")
        print("6.Send a message from bob")
        print("7.Exit")
        n = int(input("\nEnter your choice: "))

        if n == 1:
            print("hi")
            one(Alice)
        elif n == 2:
            one(Bob)
        elif n == 3:
            sen(Alice, Bob)
        elif n == 4:
            rec(Alice, Bob)
        elif n == 5:
            send(Alice, Bob)
            receive(Alice, Bob)
        elif n is 6:
            send(Bob, Alice)
            receive(Bob, Alice)
        else:
            exit

        # to loop main
        x = input("\nBack to menu?(y/Y) ")


if __name__ == "__main__":
     main()