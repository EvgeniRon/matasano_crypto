//
//  crypto_utils.c
//  matasano_crypto_set1
//Convert hex to base64
//  Created by Evgeni Ron Overchick on 4/26/16.
//  Copyright © 2016 Evgeni Ron Shtrakh. All rights reserved.

/*
 The string:

 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

 Should produce:
 SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

 */

#include "crypto_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "base64.h"

#define base64ratio (2/3)

/* Calculate the binary value of hex char */
static unsigned int char2nibble(char hex) {
	if (hex >= '0' && hex <= '9')
		return hex - '0';
	if (hex >= 'a' && hex <= 'z')
		return hex - 'a' + 10;
	if (hex >= 'A' && hex <= 'Z')
		return hex - 'A' + 10;
	return 255;
}

/* Converting each hex character to its binary representation. Than building a hex byte from two hex charcter */
void hexStr2byteArr(const char *hexStr, unsigned long str_size, u_int8 *byteArr) {
	for (int i = 0; i < (str_size) / 2; i++) {
		byteArr[i] = char2nibble(hexStr[2 * i]) << 4
				| char2nibble(hexStr[2 * i + 1]);
	}
}

void printByteArr(const u_int8 *byteArr, unsigned long length) {
	for (int i = 0; i < length; i++) {
		printf("%x", byteArr[i]);
	}
	printf("\n");
}

/* Convert hex input to base64 */
int hex2base64(const char *str, unsigned long str_len, u_int8 * OUT_base64) {
	static const char *fname = __FUNCTION__;

	unsigned int i;
	u_int8 *byteArr;
	u_int8 *base64str;
	u_int8 *base64val;

	byteArr = (u_int8 *) malloc(str_len/2);
	if (byteArr == NULL) {
		free(byteArr);
		printf("%s: Error allocating memory!\n", fname);
		return FALSE;
	}

	// convert hex string to byte array
	hexStr2byteArr(str, str_len, byteArr);

	base64val = (u_int8 *) malloc(str_len * base64ratio);
	if (base64val == NULL) {
		free(base64val);
		printf("%s: Error allocating memory!\n", fname);
		return FALSE;
	}

	// At each iteration, convert triplet of bytes to four base64 values.
	for (i = 0; i < str_len / 6; i++) {
		// High 6 bits aligned to LSB
		base64val[i * 4] = (0xFC & byteArr[i * 3]) >> 2;
		base64val[i * 4 + 1] = ((0x03 & byteArr[i * 3]) << 4)
				| ((0xF0 & byteArr[i * 3 + 1]) >> 4);
		base64val[i * 4 + 2] = ((0x0F & byteArr[i * 3 + 1]) << 2)
				| ((0xC0 & byteArr[i * 3 + 2]) >> 6);
		base64val[i * 4 + 3] = (0x3F & byteArr[i * 3 + 2]);
	}

	// Encode each value to its corresponding base64 characters
	for (i = 0; i < str_len * base64ratio; i++) {
		if (base64val[i] <= 25)
			OUT_base64[i] = base64val[i] + 'A';
		else if ((base64val[i] >= 26) && (base64val[i] <= 51))
			OUT_base64[i] = base64val[i] - 26 + 'a';
		else if ((base64val[i] >= 52) && (base64val[i] <= 61))
			OUT_base64[i] = base64val[i] - 52 + '0';
		else if (base64val[i] == 62)
			OUT_base64[i] = '+';
		else if (base64val[i] == 63)
			OUT_base64[i] = '/';
		else
			printf("%s: Error!! base64val[%d] = %d\n",fname, i, base64str[i]);
	}


	free(base64val);
	free(byteArr);

	return TRUE;
}

/* XOR between two equal length buffers	*/
int strxor(const char *stra, const char *strb, unsigned int length, unsigned char *str_result) {
	static const char *fname = __FUNCTION__;

	u_int8 str_a;
	u_int8 str_b;
	unsigned int i;

	str_a = malloc(length/2);
	if (str_a == NULL) {
		free(str_a);
		printf("%s: Error allocating memory!\n",fname);
		return FALSE;
	}
	str_b = malloc(length/2);
	if (str_a == NULL) {
		free(str_a);
		printf("%s: Error allocating memory!\n",fname);
		return FALSE;
	}

	// convert hex string to byte array
	hexStr2byteArr(stra, length, str_a);
	hexStr2byteArr(strb, length, str_b);

	for (i = 0; i < length/2; i++) {
		str_result[i] = str_a[i] ^ str_b[i];
	}
	return TRUE;
}
