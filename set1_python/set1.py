#!/usr/bin/python3.6
from functools import reduce

"""Cryptopals Set#1"""
import binascii
import base64
import math 

def hex2base64(hex_str):
    """Function to convert hex string to base64 string"""
    bin_str = binascii.unhexlify(hex_str)
    return base64.b64encode(bin_str)


def hex2b(hex):
    return binascii.unhexlify(hex)


def u_ord(charcter):
    """Adapt `ord(c)` for Python 2 or 3"""
    return ord(str(charcter)[0:1])


def xor_strings(str_a, str_b):
    """XOR two strings together https://en.wikipedia.org/wiki/XOR_cipher"""
    return "".join(chr(u_ord(a) ^ u_ord(b)) for a, b in zip(str_a, str_b))


def xor_bstrings(b_str1, b_str2):
    return bytes([x ^ y for x, y in zip(b_str1, b_str2)])


def char_frequency(string1):
    """Counting the freqeuncy of characters in a given string"""
    return dict((_char, string1.count(_char)) for _char in set(string1.upper()))


def score(message):
    def score_char(charcter):
        """Returns the likelihood that a string is a valid PT string."""
        # +1 if string is in the set of characters or spaces
        positive_set = list(range(ord('a'), ord('z'))) + [ord(' ')]
        # -1 if the string is in the set of rarely used characters:
        #   128, 153, 161-255
        negative_set = [128] + [153] + list(range(161, 255))
        # -99 if the string is in the set of unused characters:
        #   0-8, 11-31, 127, 129-152, 154-160
        unused_set = (list(range(0, 9)) + list(range(11, 32)) + [127] +
                      list(range(129, 153)) + list(range(154, 161)))
        if ord(charcter) in positive_set:
            return 1
        elif ord(charcter) in negative_set:
            return -9
        elif ord(charcter) in unused_set:
            return -99
        else:
            return 0
    return sum(map(score_char, [c for c in message]))


def decypher_single_byte_xor(cipher):
    """Single-byte XOR cipher decryption"""
    max_score_key = 0
    secret_message = ""
    key = 0
    for i in range(0, 255):
        test_key = chr(i) * len(cipher)
        message = xor_strings(test_key, hex2b(cipher).decode('utf-8'))
        key_score = score(message)
        if key_score > max_score_key:
            max_score_key = key_score
            secret_message = message
            key = i
    print("Plaintext:", secret_message)
    return (key, secret_message)


def repeating_key_xor(key, text):
    """Repeating-key XOR"""
    string_key = key * math.ceil(len(text)/len(key))
    res = xor_bstrings(string_key[:len(text)].encode('utf-8'), text.encode('utf-8'))
    return binascii.b2a_hex(res)


if __name__ == "__main__":
    from os import urandom

    def genkey(length):
        """Generate key"""
        return urandom(length)

    TEST_STR_CRYPOPASL = (
        "49276d206b696c6c696e6720796f757220627261696e206c"
        "696b65206120706f69736f6e6f7573206d757368726f6f6d"
    )
    RESULT_COMPARE_CRYPOPASL = (
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11"
        "c2hyb29t"
    )
    RESULT = (hex2base64(TEST_STR_CRYPOPASL)).decode('utf-8')

    # Verify task 01
    if RESULT == RESULT_COMPARE_CRYPOPASL:
        print('PASSED: Encoding base64 string ')
    else:
        print(' Failed')

    MESSAGE = 'This is a secret message'
    print('message:', MESSAGE)

    KEY = genkey(len(MESSAGE))
    print('key:', KEY)

    CIPHERTEXT = xor_strings(MESSAGE, KEY)
    print('cipherText:', CIPHERTEXT)
    print('decrypted:', xor_strings(CIPHERTEXT, KEY))


    # Verify task 02
    if xor_strings(CIPHERTEXT, KEY) == MESSAGE:
        print('Unit test xor_strings: passed')
    else:
        print('Unit test xor_strings: failed')

    CIPHER = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    decypher_single_byte_xor(CIPHER)

    cypher_file = open('data/4.txt', 'rb')
    for line in cypher_file:
        try:
            decypher_single_byte_xor(line.rstrip())
        except UnicodeError:
            pass


    TEXT = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    CIPHER = ("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a312"
              "4333a653e2b2027630c692b20283165286326302e27282f")
    KEY = "ICE"
    res = repeating_key_xor(KEY, TEXT)

    if (res.decode('utf-8')) == CIPHER:
        print('Unit test: repeating_key_xor passed')
    else:
        print('Unit test: repeating_key_xor failed')
        print(res.decode('utf-8'))
        print(CIPHER)
