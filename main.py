#!/usr/bin/env python3

import argparse
import string
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify
from binascii import unhexlify

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



def get_args():
    """
    Parse the CLI arguments

    usage:
    cmd
        -g generate certificate by specifing where to store it, default value .
        -cert specify name of the file --> improvement path of the file
        -m message that should be encrypt or decrypt
        -file file that will be decypt/encrypt
    """
    parser = argparse.ArgumentParser(description="Little piece of software that encrypt or decrypt a message by using pem files")

    parser.add_argument("-g", "--generate", help="generate certificate",
                        metavar="generate")
    parser.add_argument("-c","--cert",
                        help="pem file name used by the program",
                        metavar="cert")
    parser.add_argument("-m", "--message", type=str, help="message to encrypt/decypt",
                        metavar="message")
    #TODO -f need to be create
    parser.add_argument("-f", "--file", help="File to decrypt/encrypt",
                        metavar="FILE")
    parser.add_argument("-o", "--output", help="Directs the output to a name of your choice",
                        metavar="output")

    return parser.parse_args() 

def bin2hex(binStr):
    """Function to convert binary into hexa

    Parameters
    ----------
    binStr
        binary
    """
    return hexlify(binStr)

def hex2bin(hexStr):
    """Function to convert hexa into binary

    Parameters
    ----------
    hexStr
        hexadecimal
    """
    return unhexlify(hexStr)

def is_hex(s):
    """Function to test if a data is an hexa

    Parameters
    ----------
    s
        data
    """
    hex_digits = set(string.hexdigits)
    return all(c in hex_digits for c in s)

def main():
    args = get_args()
    if args.generate:
        private_pem, public_pem = generate_pem()
        write_pem(private_pem, public_pem)
    
    if args.cert and args.message:
        key = import_pem(args.cert)
        if is_hex(args.message):
            message = hex2bin(args.message)
        else:
            message = args.message.encode()
        cipher = crypto(key,message)
        # try to decode if cipher is a binary else convert into bin and then decode
        try:
            cipher = cipher.decode()
        except UnicodeDecodeError:
            cipher = bin2hex(cipher).decode()
        
        print(cipher)
        if args.output:
            with open(args.output, 'w') as output_file:
                output_file.write(cipher)

if __name__ == "__main__":
    main()
    pass