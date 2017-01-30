"""Cryptopals Set#1"""
#!/usr/bin/python3
import binascii
import base64

def hex2base64(hex_str):
    """Function to convert hex string to base64 string"""
    bin_str = binascii.unhexlify(hex_str)
    return base64.b64encode(bin_str)

TEST_STR = (
    "49276d206b696c6c696e6720796f757220627261696e206c"
    "696b65206120706f69736f6e6f7573206d757368726f6f6d"
)

RESULT = (hex2base64(TEST_STR)).decode()
RESULT_COMPARE = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
print (RESULT == RESULT_COMPARE)

