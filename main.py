#!/usr/bin/env python3

# import argparse
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

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
    """ Write keys into a file, by default the name of the file will be rivate_pem.pem and public_pem.pem save in the same folder as the script

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

def import_pem(name_pem):
    """ Import pem file and return RSA Key object 

    Parameters
    ----------
    name_pem: str
        File name containing the private key
    
    Returns
    -------
    object
        RSA key object
    """
    # TODO change the algorithme by ECC
    key = RSA.import_key(open(name_pem, 'r').read())
    return key

def crypto(key, message):
    """ Decrypt or encrypt a message with an encryption key PKCS1_OAEP and return it

    Parameters
    ----------
    key: object
        The RSA key object to use to decrypt/encrypt the message
    message: bytes
        The encrypted/plain text message
    
    Returns
    -------
    bytes
        The encrypted/plain text message
    """
    cipher = PKCS1_OAEP.new(key=key)

    if key.has_private():
        result_message = cipher.decrypt(message)
    else:
        result_message = cipher.encrypt(message)

    return result_message

private_pem, public_pem = generate_pem()
write_pem(private_pem, public_pem)

name_priv_pem = 'private_pem.pem'
name_pub_pem = 'public_pem.pem'
pu_key = import_pem(name_pub_pem)
pr_key = import_pem(name_priv_pem)

message = b'Public and Private keys encryption'

cipher_text = crypto(pu_key, message)
print(cipher_text)

decrypted_message = crypto(pr_key, cipher_text)
print(decrypted_message)