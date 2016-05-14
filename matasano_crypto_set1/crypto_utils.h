//
//  crypto_utils.h
//  matasano_crypto_set1
//
//  Created by Evgeni Ron Overchick on 4/26/16.
//  Copyright © 2016 Evgeni Ron Shtrakh. All rights reserved.
//

#ifndef crypto_utils_h
#define crypto_utils_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char BYTE;
BYTE *hex2base64(const char *str, unsigned long str_len);
BYTE *strxor(const char *stra, const char *strb, unsigned long length);
void hexStr2byteArr(const char *hexStr, unsigned long str_size, BYTE *byteArr);
void printByteArr(const BYTE *byteArr, unsigned long length);



#endif /* crypto_utils_h */
