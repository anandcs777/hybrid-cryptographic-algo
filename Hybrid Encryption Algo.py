from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
import os
from Cryptodome.Random import get_random_bytes
import random

def primeslist(x, y):
    prime_list = []
    for n in range(x, y):
        isPrime = True

        for num in range(2, n):
            if n % num == 0:
                isPrime = False

        if isPrime:
            prime_list.append(n)

    return prime_list


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def minv(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = minv(b % a, a)

        return (g, x - (b // a) * y, y)


def keygeneration():
    plist = primeslist(1000,5000)


    p = random.choice(plist)
    q = random.choice(plist)

    print("p =",p," q=",q,"\n")

    n = p * q
    phi_n = (p - 1) * (q - 1)

    i = 0
    while (i != 1):
        e = random.randint(1, phi_n)
        i = gcd(e, phi_n)

    #print(e," ",gcd(e,phi_n))

    d = minv(e, phi_n)[1]
    d = d % phi_n

    if (d < 0):
        d = d + phi_n
    return ((e,n),(d,n))



def encrypt(plain_text, password):
    # generate a random salt
    salt = get_random_bytes(AES.block_size)

    # Scrypt KDF to get a private key from the password
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)

    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }


def decrypt(enc_dict, password):
    # decode the dictionary entries from base64
    salt = b64decode(enc_dict['salt'])
    cipher_text = b64decode(enc_dict['cipher_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])

    # generate the private key from the password and salt
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)

    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # decrypt the cipher text
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted


def main():

    print("-----------------------Sender side-----------------------------")
    aeskey= input("Enter Symmetric private key: ")
    msg=input("Enter the message to encrypt: ")

    encrypted = encrypt(msg,aeskey)
    print(encrypted)

    msghash=hashlib.sha256(msg.encode("utf-8")).hexdigest()
    print("msg hash =",msghash)

    xorWord = lambda ss, cc: ''.join(chr(ord(s) ^ ord(c)) for s, c in zip(ss, cc * 100))

    xorskey=xorWord(aeskey,msghash)

    print("XOR-ed key = ",xorskey)
    #------------------------------------------------RSA---------------------------
    public_key, private_key = keygeneration()

    print("Public key =", public_key, "\n Private key =", private_key)

    ptext =str(encrypted) + "#" + str(xorskey) +"#"+ str(msghash)

    pukey,n = public_key

    entext = []
    for char in ptext:
        tt = pow(ord(char), pukey, n)
        entext.append(tt)
    print("encrypted value=", entext, "\n")



    print("--------------------Reciever Side-----------------------")

    prkey, n = private_key
    dtext = []
    for v in entext:
        r = chr(pow(v, prkey, n))
        dtext.append(r)

    print("RSA decrypted text =", dtext)


    decryptxorkey=xorWord(xorskey,msghash)

    print("Decrypted Symmetric key = ",decryptxorkey)

    decrypted = decrypt(encrypted, decryptxorkey)
    print("\n Decrypted message = ",bytes.decode(decrypted))

main()