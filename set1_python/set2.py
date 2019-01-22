#!/usr/bin/env python3

import sys
from os import urandom
import random
import unittest
import binascii
import base64
from Crypto.Cipher import AES
import secrets
import set1

def pkcs7_padding(plaintext, block_size):
    """ PKCS7 padding"""
    padding_length = block_size - len(plaintext) % block_size
    pad = padding_length * chr(padding_length)
    return b''.join([plaintext, pad.encode()])
    
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

def pkcs7_decode(block, k=16):
    """ Remove the PKCS#7 padding from a text bytestring """

    padding_value = block[-1]
    if padding_value > k:
        raise ValueError("Input is not padded or padding is corrupt")
    n = len(block) - padding_value
    return block[:n]

def encrypt_aes_in_ecb_mode(plaintext, key):
    """ AES encryption in ECB mode"""
    if len(plaintext) % len(key):
        plaintext = pkcs7_padding(plaintext, len(key))

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

def get_random_bytes(length=16):
    """ Generate N random bytes byte string """
    return secrets.token_bytes(length)

def encryption_oracle(message):
    """Detectction orable - detects the block cipher mode, ECB or CBC """
    key = get_random_bytes()
    left_pad = random.randint(5, 10)
    right_pad = random.randint(5, 10)
    plaintext = get_random_bytes(left_pad) + message.encode() + get_random_bytes(right_pad)
    if(random.randint(0, 1)) == 2:
        return encrypt_aes_in_ecb_mode(plaintext, key)
    else:
        init_vector = get_random_bytes()
        return encrypt_cbc_mode(plaintext, key, init_vector)

class EncryptionOracle:
    """ Encryption oracle """
    def __init__(self, mode):
        self.__key = get_random_bytes()
        self.__left_pad = random.randint(5, 10)
        self.__right_pad = random.randint(5, 10)
        if mode is "random":
            if random.randint(0, 1) == 0:
                self.__mode = "ECB"
            else:
                self.__mode = "CBC"
        elif mode is "ECB":
            self.__mode = "ECB"
        elif mode is "CBC":
            self.__mode = "CBC"

    def encrypt(self, message):
        """ Encrypt a message """
        self.__plaintext = get_random_bytes(self.__left_pad) + message.encode() + get_random_bytes(self.__right_pad)
        if self.__mode is "ECB":
            self.cipher = encrypt_aes_in_ecb_mode(self.__plaintext, self.__key)
        else:
            self.__init_vector = get_random_bytes()
            self.cipher = encrypt_cbc_mode(self.__plaintext, self.__key, self.__init_vector)

    def get_plaintext(self):
        """ Returns the message after concatenating to it random bytes """
        return self.__plaintext

    def get_mode(self):
        """Return the encryption type that was used"""
        return self.__mode

    def flip_a_coin(self):
        """Choose encrypyion type randomly"""
        if random.randint(0, 1) == 0:
            self.__mode = "ECB"
        else:
            self.__mode = "CBC"


def detect_oracle_encryption(oracle):
    """Detect oracles encryption"""
    extra_padding = 11
    block_size = 16
    number_of_blocks = 2
    message = "A" * (extra_padding + block_size * number_of_blocks)
    oracle.encrypt(message)
    if set1.detect_AES_in_ECB_ciphertext(oracle.cipher, block_size):
        return "ECB"
    else:
        return "CBC"

class AESEncryptionOracle:
    """ Encrypt Input and a secret message """
    """ AES_ECB(INPUT + SECRET, KEY) """
    def __init__(self, secret_message):
        self.__key = get_random_bytes()
        self.secret_message = secret_message
        self.__mode = "ECB"

    def encrypt(self, message):
        """ Encrypt a message """
        self.__plaintext = message.encode() + base64.b64decode(self.secret_message + '=' * (-len(self.secret_message) % 4)) 
        self.cipher = encrypt_aes_in_ecb_mode(self.__plaintext, self.__key)
        return self.cipher

    def get_plaintext(self):
        """ Returns the message after concatenating to it random bytes """
        return self.__plaintext

def discover_block_size(oracle, bs_limit):
    """ Discover block size of the encryption """
    for bs in range(1, bs_limit):
        bs_string = "A" * bs
        bs_string_double = bs_string * 2
        cipher_a = oracle.encrypt(bs_string)
        cipher_b = oracle.encrypt(bs_string_double)
        if cipher_a in cipher_b[bs:]:
            return bs

    return 0
#def byte_at_a_time_ecb_simple(aes_oracle):
#    """ Discover secret message - AES byte at a time """


    


class My_tests(unittest.TestCase):
    """ Test Set2 methods """

    def test_pkcs7_encode(self):
        """test pkcs7 padding"""
        block = "YELLOW SUBMARINE"
        result = "YELLOW SUBMARINE\x04\x04\x04\x04"
        boundry = 20
        self.assertEqual(pkcs7_encode(block.encode(), boundry), result.encode())

    def test_pkcs7_decode(self):
        """ Test pkcs7 unpadding """
        block = "YELLOW SUBMARINE\x04\x04\x04\x04".encode()
        result = "YELLOW SUBMARINE"
        boundry = 20
        self.assertEqual(pkcs7_decode(block, boundry), result.encode())

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
        self.assertTrue(plaintext.decode().find('Play'))

    def test_encryption_oracle(self):
        """ Testing encryption oracle """
        ciphertext = "testing block"
        #print("cipher: ", encryption_oracle(ciphertext))

    def test_oracleClass(self):
        """ Testing encryption oracle """
        text = "testing oracle class"
        oracle = EncryptionOracle("random")
        oracle.encrypt(text)
       # print("mode = ", oracle.get_mode(), "\n")
       # print("oracle.cipher: ", oracle.cipher, "\n")
        mode = oracle.get_mode()
        while(mode is oracle.get_mode()):
            oracle.flip_a_coin()
            oracle.encrypt(text)
       # print("mode = ", oracle.get_mode(), "\n")
       # print("oracle.cipher: ", oracle.cipher, "\n")

    def test_detect_oracle_encryption(self):
        """Test oracle encryption detection"""
        oracle_random = EncryptionOracle("random")
        result = detect_oracle_encryption(oracle_random)
        self.assertEqual(result, oracle_random.get_mode())
        oracle_ecb = EncryptionOracle("ECB")
        result = detect_oracle_encryption(oracle_ecb)
        self.assertEqual(result, oracle_ecb.get_mode())
        oracle_cbc = EncryptionOracle("CBC")
        result = detect_oracle_encryption(oracle_cbc)
        self.assertEqual(result, oracle_cbc.get_mode())

    def test_discover_block_size(self):
        """Test block size discovery"""
        oracle = AESEncryptionOracle("My secret message")
        block_size = discover_block_size(oracle, 40)
        self.assertEqual(block_size, 16)



if __name__ == "__main__":
    suite = unittest.TestSuite()
    suite.addTest(My_tests("test_discover_block_size"))
    runner = unittest.TextTestRunner()
    runner.run(suite)
    #unittest.main()


