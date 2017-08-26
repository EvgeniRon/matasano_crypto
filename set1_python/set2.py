#!/usr/bin/env python3

import sys
from os import urandom
import unittest
import time

"""Cryptopals Set#1"""
import binascii
import base64

def pkcs7_padding(block, boundry):
    """Padding is in whole bytes. The value of each added byte is the number of bytes that are added, i.e. N bytes, each
    of value N are added. The number of bytes added will depend on the block boundary to which the message needs to be
    extended."""

    delta = boundry - len(block)
    if delta <= 0:
        return block
    return ''.join([block, delta*str(chr(delta))])

class My_tests(unittest.TestCase):
    """ Test Set2 methods """

    def test_pkcs7_padding(self):
        """ Test pkcs7 padding """
        block = "YELLOW SUBMARINE"
        boundry = 20
        self.assertEqual(pkcs7_padding(block, boundry), "YELLOW SUBMARINE\x04\x04\x04\x04")

if __name__ == "__main__":
    suite = unittest.TestSuite()
    suite.addTest(My_tests("test_pkcs7_padding"))
    runner = unittest.TextTestRunner()
    runner.run(suite)
