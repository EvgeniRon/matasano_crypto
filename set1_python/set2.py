#!/usr/bin/env python3

import sys
from os import urandom
import unittest
import binascii
import base64
from Crypto.Cipher import AES
import set1


def pkcs7_padding(block, boundry):
    """Padding is in whole bytes. The value of each added byte is the number of bytes that are added, i.e. N bytes, each
    of value N are added. The number of bytes added will depend on the block boundary to which the message needs to be
    extended."""

    delta = boundry - len(block)
    if delta <= 0:
        return block
    return ''.join([block, delta*str(chr(delta))])

def encrypt_aes_in_ecb_mode(plaintext, key):
    """ AES encryption in ECB mode"""

    encryption_suite = AES.new(key, AES.MODE_ECB)
    return encryption_suite.encrypt(plaintext)

def encrypt_cbc_mode(plaintext, key, init_vector):
    """Implementation of CBC mode encryption of irregularly-sized messages"""

    key_size = len(key)
    assert key_size == 16 or key_size == 128 or key_size == 256
    cipher_list = []
    divided_content = list(set1.divide_to_nlength_strings(plaintext, key_size))
    if  len(plaintext) % key_size:
        divided_content[-1] = pkcs7_padding(divided_content[-1], key_size)

    for block in divided_content:
        message = set1.xor_strings(init_vector, block)
        ciphered_message = encrypt_aes_in_ecb_mode(message, key)
        cipher_list.append(ciphered_message)
        init_vector = binascii.hexlify(ciphered_message).decode()
    return b"".join(cipher_list)

def decrypt_aes_in_cbc_mode(ciphertext, key, init_vector):
    """ Decryption of AES in CBC mode """
    key_size = len(key)
    plaintext_list = []
    padding_length = 0
    assert key_size == 16 or key_size == 128 or key_size == 256
    divided_content = list(set1.divide_to_nlength_strings(ciphertext, key_size))
    for block in divided_content:
        decrypted_str = set1.decrypt_AES_in_ECB_mode(block, key).decode()
        xor_decrypted = set1.xor_strings(init_vector, decrypted_str)
        if divided_content[-1] == block:
            padding_length = ord(xor_decrypted[-1])
        plaintext_list.append(xor_decrypted[0:(key_size - padding_length)])
        init_vector = binascii.hexlify(block).decode()
    return ''.join(plaintext_list)

class My_tests(unittest.TestCase):
    """ Test Set2 methods """

    def test_pkcs7_padding(self):
        """ Test pkcs7 padding """
        block = "YELLOW SUBMARINE"
        boundry = 20
        self.assertEqual(pkcs7_padding(block, boundry), "YELLOW SUBMARINE\x04\x04\x04\x04")

    def test_encrypt_aes_in_ecb_mode(self):
        """ Test AES in ECB mode encryption"""
        key = "PURPLE WATERFALL"
        plaintext = "YELLOW SUBMARINE"
        cipher = encrypt_aes_in_ecb_mode(plaintext, key)
        decrypted = set1.decrypt_AES_in_ECB_mode(cipher, key)
        self.assertEqual(decrypted.decode(), plaintext)

    def test_encrypt_aes_in_cbc_mode(self):
        """ Test AES in CMC mode encryption """
        key = "PURPLE WATERFALL"
        plaintext = "YELLOW SUBMARINE hello world"
        init_vector = "fake 0th ciphertext block"
        cipher = encrypt_cbc_mode(plaintext, key, init_vector)
        self.assertEqual(decrypt_aes_in_cbc_mode(cipher, key, init_vector), plaintext)



if __name__ == "__main__":
    suite = unittest.TestSuite()
    suite.addTest(My_tests("test_encrypt_aes_in_cbc_mode"))
    runner = unittest.TextTestRunner()
    runner.run(suite)

