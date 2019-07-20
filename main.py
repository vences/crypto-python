#!/usr/bin/env python3

# import argparse
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify

def generate_pem():
    """ Generate private and public key from RSA with a length of 1024 bits

    Returns
    -------
    str 
        private key
    str
        public key
    """
    # TODO change the key algorithm to ECC curve P-384
    private_key = RSA.generate(1024)
    public_key = private_key.publickey()

    private_pem = private_key.export_key().decode()
    public_pem = public_key.export_key().decode()

    return private_pem, public_pem

def write_pem(private_pem, public_pem):
    """ Write into a file the keys objects, by default the name of the file will be rivate_pem.pem and public_pem.pem save in the same folder as the script

    Parameters
    ----------
    private_pem: str
        the string containing the private key
    public_pem: str
        the string containing the public key
    """
    with open('private_pem.pem', 'w') as pr:
        pr.write(private_pem)
    with open('public_pem.pem', 'w') as pu:
        pu.write(public_pem)

def import_pem(name_priv_pem, name_pub_pem):
    """ Import private and public from the file name parameters into 2 strings variable 

    Parameters
    ----------
    name_priv_pem: str
        File name containing the private key
    name_pub_pem: str
        File name containing the public key
    
    Returns
    -------
    object
        RSA private key object
    object
        RSA public key object
    """
    # TODO change the algorithme by ECC
    pr_key = RSA.import_key(open('private_pem.pem', 'r').read())
    pu_key = RSA.import_key(open('public_pem.pem', 'r').read())
    return pr_key, pu_key

def encrypt(pu_key, message):
    """ Encrypt a message with an encryption key PKCS1_OAEP and return it

    Parameters
    ----------
    pu_key: object
        The RSA key object to use to encrypt the message
    message: bytes
        Plain text message to encrypt
    
    Returns
    -------
    bytes
        The ciphertext
    """
    cipher = PKCS1_OAEP.new(key=pu_key)
    cipher_text = cipher.encrypt(message)
    return cipher_text

def decrypt(pr_key, cipher_text):
    """ Decrypt a message with an encryption key PKCS1_OAEP and return it

    Parameters
    ----------
    pr_key: object
        The RSA key object to use to decrypt the message
    cipher_text: bytes
        The encrypted message
    
    Returns
    -------
    bytes
        The plain text message
    """
    cipher = PKCS1_OAEP.new(key=pr_key)
    decrypted_message = cipher.decrypt(cipher_text)
    return decrypted_message

private_pem, public_pem = generate_pem()
write_pem(private_pem, public_pem)

name_priv_pem = 'private_pem.pem'
name_pub_pem = 'public_pem.pem'
pr_key, pu_key = import_pem(name_priv_pem, name_pub_pem)

message = b'Public and Private keys encryption'

cipher_text = encrypt(pu_key, message)
print(cipher_text)

decrypted_message = decrypt(pr_key, cipher_text)
print(decrypted_message)