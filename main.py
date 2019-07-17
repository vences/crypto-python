#!/usr/bin/env python3

# RSA_cryptography.py
# Importing necessary modules
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify#The message to be encrypted
message = b'Public and Private keys encryption'

def generate_pem():
    # Generating private key (RsaKey object) of key length of 1024 bits
    private_key = RSA.generate(1024)
    # Generating the public key (RsaKey object) from the private key
    public_key = private_key.publickey()
    # Converting the RsaKey objects to string 
    private_pem = private_key.export_key().decode()
    public_pem = public_key.export_key().decode()
    return private_pem, public_pem

def write_pem(private_pem, public_pem):
    # Writing down the private and public keys to 'pem' files
    with open('private_pem.pem', 'w') as pr:
        pr.write(private_pem)
    with open('public_pem.pem', 'w') as pu:
        pu.write(public_pem)
    return

def import_pem(name_priv_pem, name_pub_pem):
    # Importing keys from files, converting it into the RsaKey object 
    # filename input('file name')  
    pr_key = RSA.import_key(open('private_pem.pem', 'r').read())
    pu_key = RSA.import_key(open('public_pem.pem', 'r').read())
    return pr_key, pu_key

def encrypt(pu_key):
    # Instantiating PKCS1_OAEP object with the public key for encryption
    cipher = PKCS1_OAEP.new(key=pu_key)
    # Encrypting the message with the PKCS1_OAEP object
    cipher_text = cipher.encrypt(message)
    return cipher_text

def decrypt(pr_key):
    # Instantiating PKCS1_OAEP object with the private key for decryption
    decrypt = PKCS1_OAEP.new(key=pr_key)
    # Decrypting the message with the PKCS1_OAEP object
    decrypted_message = decrypt.decrypt(cipher_text)
    return decrypted_message

private_pem, public_pem = generate_pem()
print(type(private_pem), type(public_pem))
write_pem(private_pem, public_pem)

name_priv_pem = 'private_pem.pem'
name_pub_pem = 'public_pem.pem'
pr_key, pu_key = import_pem(name_priv_pem, name_pub_pem)
print(type(pr_key), type(pu_key))

cipher_text = encrypt(pu_key)
print(cipher_text)

decrypted_message = decrypt(pr_key)
print(decrypted_message)