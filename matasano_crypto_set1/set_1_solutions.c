//
//  set_1_solutions.c
//  matasano crypto set1 solution
//
//  Created by Evgeni Ron Overchick on 4/26/16.
//

#include <stdio.h>
#include "crypto_utils.h"
#include "single_byte_xor_cipher.h"


int main(int argc, const char * argv[]) {
    static const char fname = __FUNCTION__;

    /*  Hex to base64 challenge */
    char challenge1_test [] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    char challenge1_solution [] = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    /*  Fixed XOR challenge */
    char stra[] = "1c0111001f010100061a024b53535009181c";
    char strb[] = "686974207468652062756c6c277320657965";
    char stra_xor_strb[] = "746865206b696420646f6e277420706c6179";
    
    char result[] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    u_int8 *base64_result;
    u_int8 *base64_result2;
    u_int8 *str_xor_res;    

    /* HEX2BASE64 test */
    printf("hex2base64 test:\n");
    
    base64_result = (u_int8*)malloc(sizeof(test_string)*base64ratio);
    if(base64_result == NULL) {
        printf("%s: Error allocating memory!\n",fname);
        free(base64_result);
        return FALSE;
    }

    if (!hex2base64(challenge1_test, sizeof(challenge1_test), base64_result)) {
        printf("hex2base64 failed!");
        free(base64_result);
    }

    base64_result2 = (u_int8*)malloc(BASE64_DECODE_OUT_SIZE(sizeof(test_string)));
    if(base64_result2 == NULL) {
        printf("%s: Error allocating memory!\n",fname);
        free(base64_result2);
        return FALSE;
    }

    if(base64_decode(challenge1_test, sizeof(test_string), base64_result2)) {
        printf("base64_decode failed!\n");
    }
  
    if (strcmp(base64_result, challenge1_solution)){
        printf("hex2base64 string compare failed!\n");
    }
   
    if (strcmp(base64_result2, challenge1_solution)) {
        printf("base64_decode string compare failed!\n");
    }

    /* strxor test */
    str_xor_res = (u_int8*)malloc(strlen(stra)/2);
    if(str_xor_res == NULL) {
        printf("Error allocating memory!\n");
        free(str_xor_res);
        return FALSE;
    }

    if(!strxor(stra, strb, strlen(stra), str_xor_res)) {
        printf("strxor failed!\n");
    }
    
    if (strcmp(str_xor_res, stra_xor_strb)) {
        printf("strxor string compare failed!\n");
    }
    
    /* fixed byte XOR cipher tests */
    pt = break_cipher(cp, PENALTY, DISTANCE_SCORING);

exit: 
        free(base64_result);
        free(base64_result2);
    
    getchar();        
    return TRUE;

}
