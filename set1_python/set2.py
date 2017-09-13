#!/usr/bin/env python3

import sys
from os import urandom
import unittest
import binascii
import base64
from Crypto.Cipher import AES
import secrets
import set1


def pkcs7_encode(block, boundry):
    """Padding is in whole bytes. The value of each added byte is the number of bytes that are added, i.e. N bytes, each
    of value N are added. The number of bytes added will depend on the block boundary to which the message needs to be
    extended."""

    delta = boundry - len(block)
    if delta <= 0:
        return block
    #return ''.join([block, delta*str(chr(delta))])
    tmp = block + bytearray([delta]*delta)
    return tmp

def pkcs7_decode(block, k = 16):
    """ Remove the PKCS#7 padding from a text bytestring """
    
    padding_value = block[-1]
    if padding_value > k:
        raise ValueError("Input is not padded or padding is corrupt")
    n = len(block) - padding_value
    return block[:n]

def encrypt_aes_in_ecb_mode(plaintext, key):
    """ AES encryption in ECB mode"""

    encryption_suite = AES.new(key, AES.MODE_ECB)
    return encryption_suite.encrypt(plaintext)

def encrypt_cbc_mode(plaintext, key, init_vector):
    """Implementation of CBC mode encryption of irregularly-sized messages"""

    key_size = len(key)
    assert  key_size == 16 or key_size == 128 or key_size == 256
    cipher_list = []
    divided_content = list(set1.divide_to_nlength_strings(plaintext, key_size))
    if  len(plaintext) % key_size:
        divided_content[-1] = pkcs7_encode(divided_content[-1], key_size)

    for block in divided_content:
        message = set1.xor_bstrings(init_vector, block)
        ciphered_message = encrypt_aes_in_ecb_mode(message, key)
        cipher_list.append(ciphered_message)
        init_vector = ciphered_message
    return b"".join(cipher_list)

def decrypt_aes_in_cbc_mode(ciphertext, key, init_vector):
    """ Decryption of AES in CBC mode """
    key_size = len(key)
    plaintext_list = []
    padding_length = 0
    assert key_size == 16 or key_size == 128 or key_size == 256
    divided_content = list(set1.divide_to_nlength_strings(ciphertext, key_size))
    for block in divided_content:
        decrypted_str = set1.decrypt_AES_in_ECB_mode(block, key)
        xor_decrypted = set1.xor_bstrings(init_vector, decrypted_str)
        if divided_content[-1] == block:
            xor_decrypted = pkcs7_decode(xor_decrypted)
        plaintext_list.append(xor_decrypted)
        init_vector = block
    return b''.join(plaintext_list)

def get_random_key(length):
    """ Generate N random bytes byte string """
    return secrets.token_bytes(length)


class My_tests(unittest.TestCase):
    """ Test Set2 methods """

    def test_pkcs7_decode(self):
        """ Test pkcs7 padding """
        block = "YELLOW SUBMARINE"
        boundry = 20
        self.assertEqual(pkcs7_decode(block, boundry), "YELLOW SUBMARINE\x04\x04\x04\x04".encode())

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
        cipher = encrypt_cbc_mode(plaintext.encode(), key.encode(), init_vector.encode())
        deciphered_pt = decrypt_aes_in_cbc_mode(cipher, key.encode(), init_vector.encode())
        self.assertEqual(deciphered_pt.decode(), plaintext)

    def test_challenge_file(self):
        """ Decrypt challenge file """
        cipher_file = "data/10.txt"
        key = "YELLOW SUBMARINE"
        IV = 16 * '\x00'
        ciphertext = set1.openb64_file(cipher_file)
        plaintext = decrypt_aes_in_cbc_mode(ciphertext, key.encode(), IV.encode())
        if 'Play' in plaintext.decode():
            self.assertTrue(True)
        else:
            self.assertTrue(False)

if __name__ == "__main__":
    suite = unittest.TestSuite()
    suite.addTest(My_tests("test_challenge_file"))
    runner = unittest.TextTestRunner()
    runner.run(suite)

