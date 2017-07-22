#!/usr/bin/python3.6
from functools import reduce
import sys
from os import urandom
import unittest
import time

"""Cryptopals Set#1"""
import binascii
import base64
import math

def genkey(length):
    """Generate key"""
    return urandom(length)


def hex2base64(hex_str):
    """Function to convert hex string to base64 string"""
    bin_str = binascii.unhexlify(hex_str)
    return base64.b64encode(bin_str)


def hex2b(hex):
    size = len(hex)
    if size%2:
        res = binascii.b2a_hex(bin(int(hex,16))[2:].encode())
    else:
        res = binascii.unhexlify(hex)
    return  res


def u_ord(charcter):
    """Adapt `ord(c)` for Python 2 or 3"""
    return ord(str(charcter)[0:1])

def xor_strings(str_a, str_b):
    """XOR two strings together"""
    return "".join(chr((ord(a) ^ ord(b))) for a,b in zip (list(str_a), list(str_b)))

def xor_strings_legacy(str_a, str_b):
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
        message = xor_strings(test_key, cipher)
        key_score = score(message)
        if key_score > max_score_key:
            max_score_key = key_score
            secret_message = message
            key = i
    return (key, secret_message)


def repeating_key_xor(key, text):
    """Repeating-key XOR"""
    string_key = key * math.ceil(len(text)/len(key))
    return xor_strings(string_key, text)


def hamming_distance(string_a, string_b):
    """Calculating hamming/edit distance between two strings"""
    if len(string_a) != len(string_b):
        raise ValueError("Undefined for sequences of unequal length")
    bin_string_a = bin(int(binascii.hexlify(string_a.encode()), 16))[2:]
    bin_string_b = bin(int(binascii.hexlify(string_b.encode()), 16))[2:]
    return (sum(int(bit1, 2) ^ int(bit2, 2) for bit1, bit2 in zip(bin_string_a, bin_string_b)))/len(string_a)


def hamming_distance_bytes(bytearr_a, bytearr_b):
    """Calculating hamming/edit distance between two byte arrays"""
    if len(bytearr_a) != len(bytearr_b):
        raise ValueError("Undefined for sequences of unequal length")
    bin_string_a = bin(int.from_bytes(bytearr_a, sys.byteorder))[2:]
    bin_string_b = bin(int.from_bytes(bytearr_b, sys.byteorder))[2:]
    return (sum(int(bit1, 2) ^ int(bit2, 2) for bit1, bit2 in zip(bin_string_a, bin_string_b)))/len(string_a)


def hamming_distance_simple(stra, strb):
    if len(stra) != len(strb):
        raise ValueError("Undefined for sequences of unequal length")
    x = 0
    for lettera, letterb in zip(stra, strb):
        x = x + bin(ord(lettera) ^ ord(letterb)).count("1")
    #print("keysize is: ", len(stra), "hamming score: ", x/len(stra))
    return float(x/len(stra))


def guess_keysize(string_cipher, max_key_size, num_elements):
    """Calculating the most probable key size using hamming distance"""
    if max_key_size < 2:
        raise ValueError("Maximal key size must be greater or equal than 2")
    if num_elements < 1:
        raise ValueError("Number of elements must be greater than 1")
    upper_limit = len(string_cipher)//(2*num_elements) + 1
    if upper_limit < 3:
        raise ValueError("Maximal key size must be within the range of (2:len(string_cipher)//(2*num_elements) + 1]")

    normalized_scores = []
    for i in range(2, max_key_size):
        score = 0
        for j in range(num_elements):
            stra = string_cipher[i*j:i*j+i]
            strb = string_cipher[i*j+i:i*j+i*2]
            score = score + hamming_distance_simple(stra, strb)
        normalized_scores.append(score/num_elements)
    return normalized_scores


def divide_to_nlength_strings(text, length):
    """Breaking text into blocks of n length"""
    return (text[0 + i: length + i] for i in range(0, len(text), length))


def transpose_list(string_list, length):
    """Creates a block that is the first byte of every block, and a second block that is the second byte of every block,
    and so on"""
    transposed_string_list = []
    transposed_block = []
    for byte in range(length):
        for block in range(len(string_list)):
            if len(string_list[block]) < length:
                break
            transposed_block.append(string_list[block][byte])
        transposed_string_list.append(''.join(transposed_block))
        transposed_block = []
    return transposed_string_list

def decipher_blocks(transposed_block_list):
    """Solve for each block as if it was single charcter XOR"""
    repeated_xor_key = []
    for block in transposed_block_list:
        key, secret_message = decypher_single_byte_xor(block)
        repeated_xor_key.append(chr(key))
    return ''.join(repeated_xor_key)


def decipher_repeating_xor_key_encryption(file, top_n_key_sizes, max_key_size, num_of_elements):
    """Break repeating-key xor"""
    with open(file, 'r') as f:
        content = f.read()
        content = content.replace('\n', '')
        content = base64.b64decode(content).decode()

    key_sizes_stats = guess_keysize(content, max_key_size, num_of_elements)
    key_sizes_sorted = sorted(range(len(key_sizes_stats)), key = lambda k: key_sizes_stats[k])
    for key_size_index in range(top_n_key_sizes):
        divided_content = []
        transposed_divided_content = []
        key_size = 2 + key_sizes_sorted[key_size_index]
        divided_content = list(divide_to_nlength_strings(content, key_size))
        transposed_divided_content = transpose_list(divided_content, key_size)
        key = decipher_blocks(transposed_divided_content)
        text = repeating_key_xor(key, content)
        text_score = score(text)
        if text_score > 0:
            with open("".join([str(text_score), ".txt"]), 'w') as fw:
                fw.write(text)
        print("key is: ", key, "score is: ", text_score)


class My_tests(unittest.TestCase):

    def test_hex2base64(self):

        TEST_STR_CRYPOPASL = (
            "49276d206b696c6c696e6720796f757220627261696e206c"
            "696b65206120706f69736f6e6f7573206d757368726f6f6d"
        )
        RESULT_COMPARE_CRYPOPASL = (
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11"
            "c2hyb29t"
        )
        self.assertEqual(hex2base64(TEST_STR_CRYPOPASL).decode('utf-8'), RESULT_COMPARE_CRYPOPASL)

    def test_xor_strings(self):

        MESSAGE = 'This is a secret message'
        KEY = genkey(len(MESSAGE))
        CIPHERTEXT = xor_strings(MESSAGE, KEY)
        self.assertEqual(xor_strings(CIPHERTEXT, KEY), MESSAGE)

    def test_decypher_single_byte_xor(self):

        CIPHER = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        PLAINTEXT = "Cooking MC's like a pound of bacon"
        self.assertEqual(decypher_single_byte_xor(CIPHER)[1], PLAINTEXT)

    def test_on_file_decypher_single_byte_xor(self):

        PLAINTEXT = "Now that the party is jumping\n"
        cypher_file = open('data/4.txt', 'rb')
        for line in cypher_file:
            try:
                res = decypher_single_byte_xor(line.rstrip())[1]
                if  res == PLAINTEXT:
                    break
            except UnicodeError:
                pass
        cypher_file.close()

        self.assertEqual(res, PLAINTEXT)

    def test_repeating_key_xor(self):

        TEXT = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        CIPHER = ("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765"
                  "272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
        KEY = "ICE"
        self.assertEqual(repeating_key_xor(KEY, TEXT), CIPHER)


    def test_hamming_distance(self):

        STRING_TEST1 = "this is a test"
        STRING_TEST2 = "wokka wokka!!!"
        self.assertEqual(hamming_distance(STRING_TEST1, STRING_TEST2), 36)

    def test_guess_keysize(self):

        STRING_TEST1 = "test1test2"
        self.assertEqual(guess_keysize(STRING_TEST1, 2))

    def test_divide_to_nlength_strings(self):

        STRING_TEST1 = "11223344"
        KEY_SIZE = 2
        divided_content = list(divide_to_nlength_strings(STRING_TEST1, KEY_SIZE))
        self.assertEqual(len(divided_content), len(STRING_TEST1)/KEY_SIZE)

        #TODO: def test_transpose_list
        #TODO: def test_decipher_block


if __name__ == "__main__":
    suite = unittest.TestSuite()
    suite.addTest(My_tests("test_divide_to_nlength_strings"))
    runner = unittest.TextTestRunner()
    runner.run(suite)
    #top_results = 5
    #max_key_size = 40
    #num_of_elements = 4
    #decipher_repeating_xor_key_encryption("data/6.txt", top_results, max_key_size, num_of_elements)

