//
//  crypto_utils.h
//  matasano_crypto_set1
//
//  Created by Evgeni Ron Overchick on 4/26/16.
//  Copyright © 2016 Evgeni Ron Shtrakh. All rights reserved.
//

#ifndef crypto_utils_h
#define crypto_utils_h

#define FALSE	0
#define TRUE	1

typedef unsigned char u_int8;


int
hex2base64(const char *str, unsigned long str_len, u_int8 *OUT_base64);

int
strxor(const char *stra, const char *strb, unsigned int length, unsigned char *str_result);

void
hexStr2byteArr(const char *hexStr, unsigned long str_size, u_int8 *byteArr);

void
printByteArr(const u_int8 *byteArr, unsigned long length);



#endif /* crypto_utils_h */
