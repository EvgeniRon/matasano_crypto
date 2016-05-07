//
//  crypto_utils_test.c
//  matasano_crypto_set1
//
//  Created by Evgeni Ron Overchick on 4/26/16.
//  Copyright © 2016 Evgeni Ron Shtrakh. All rights reserved.
//


/*  crypto_utils_test.c tests the utility functions.
 *
 */

#include <stdio.h>
#include <string.h>
#include "crypto_utils.h"

int main(int argc, const char * argv[]) {
    char test_string [] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    char compare_string [] = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    char stra[] = "1c0111001f010100061a024b53535009181c";
    char strb[] = "686974207468652062756c6c277320657965";
    char xor_res[] = "746865206b696420646f6e277420706c6179";
    BYTE *result;
    unsigned int string_size = sizeof(test_string);
    
    printf("hex2base64 test:\n");
    result = hex2base64(test_string, string_size);
    printf("%s\n",result);
    if ( strcmp((const char*)result,compare_string) == 0){
        printf("String compare passed!\n");
    } else {
        printf("Stroing compare failed!\n");
    }
    free(result);
    
    result = strxor(stra, strb, (unsigned int)strlen(stra));
    printByteArr(result,(unsigned int)strlen(stra)/2);
    
    return 0;
}
