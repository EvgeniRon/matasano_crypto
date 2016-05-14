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
static unsigned int char2nibble (char hex);

/* Function calculateד the binary value of hex char */
static unsigned int char2nibble (char hex) {
    if ( hex >= '0' && hex <= '9' ) return hex - '0';
    if ( hex >= 'a' && hex <= 'z' ) return hex - 'a' + 10;
    if ( hex >= 'A' && hex <= 'Z' ) return hex - 'A' + 10;
    return 255;
}

/* Converting each hex character to its binary representation. Than building a hex byte from two hex charcter */
void hexStr2byteArr(const char *hexStr, unsigned long str_size, BYTE *byteArr){
    for (int i = 0; i < (str_size)/2 ; i++){
        byteArr[i] = char2nibble(hexStr[2*i])<< 4 | char2nibble(hexStr[2*i+1]);
    }
}

void printByteArr(const BYTE *byteArr, unsigned long length){
    for (int i = 0 ; i< length; i++){
        printf("%x",byteArr[i]);
    }
    printf("\n");
}

/* Function: Converts hex input to base64 */
BYTE *hex2base64(const char *str, unsigned long str_len){
    unsigned int i;
    // allocate new byte array
    BYTE *byteArr = (BYTE *)malloc(str_len/2);
    if (byteArr == NULL){
        free(byteArr);
        printf("Error allocating memory!\n");
    }

    // convert hex string to byte array
    hexStr2byteArr(str, str_len, byteArr);
    
    // allocate enough memory for base64 string
    BYTE *base64str =(BYTE *)malloc((str_len*2/3));
    if (base64str == NULL){
        free(base64str);
        printf("Error allocating memory!\n");
    }
    
    // allocate enough memory for an array which will be holding base64 int values
    BYTE  *base64val = (BYTE *)malloc((str_len*2/3));
    if (base64val == NULL){
        free(base64val);
        printf("Error allocating memory!\n");
    }

    
    // At each iteration, convert triplet of bytes to four base64 values.
    for ( i = 0; i < str_len/6; i++){
        // High 6 bits alinged to lsb
        base64val[i*4] = (0xFC & byteArr[i*3]) >> 2;
        base64val[i*4+1] = ((0x03 & byteArr[i*3]) << 4)  | ((0xF0 & byteArr[i*3+1]) >> 4);
        base64val[i*4+2] = ((0x0F & byteArr[i*3+1]) << 2) | ((0xC0 & byteArr[i*3+2]) >> 6);
        base64val[i*4+3] = (0x3F & byteArr[i*3+2]);
    }
    
    // Encode each value to its corresponding base64 characters
    for ( i = 0; i< str_len*2/3; i++ ){
        if (base64val[i] <= 25)
            base64str[i] = base64val[i]  + 'A';
        else if((base64val[i]>=26) && (base64val[i]<=51))
            base64str[i] = base64val[i] - 26 + 'a';
        else if((base64val[i]>=52) && (base64val[i]<= 61))
            base64str[i] = base64val[i] - 52 + '0';
        else if(base64val[i]  == 62)
            base64str[i] = '+';
        else if(base64val[i]  == 63)
            base64str[i] = '/';
        else
            printf("Error!! base64val[%d] = %d\n",i,base64str[i]);
    }
    
    free(base64val);
    free(byteArr);
    return base64str;
}

/* Function takes two equal length buffers and produces their XOR combination*/
BYTE *strxor(const char *stra, const char *strb, unsigned long length){
    BYTE byte_str_a[length/2],byte_str_b[length/2];
    unsigned int i;
    
    // allocate new byte array
    BYTE *str_xor_result = (BYTE *)malloc(length/2);
    if (str_xor_result == NULL){
        free(str_xor_result);
        printf("str_xor_result: Error allocating memory!\n");
    }
    
    // convert hex string to byte array
    hexStr2byteArr(stra, length, byte_str_a);
    hexStr2byteArr(strb, length, byte_str_b);
    
    for (i = 0; i < length/2; i++){
        str_xor_result[i] = byte_str_a[i] ^ byte_str_b[i];
    }
    
    return str_xor_result;
}



