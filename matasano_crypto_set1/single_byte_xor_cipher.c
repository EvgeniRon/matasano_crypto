//
//  single_byte_xor_cipher.c
//  matasano_crypto_set1
//
//  Created by Evgeni Ron Shtrakh on 5/7/16.
//  Copyright © 2016 Evgeni Ron Shtrakh. All rights reserved.
//

#include "single_byte_xor_cipher.h"
#include <math.h>

#define ENGLISH_LETTERS 26
#define ASCII_SYMBOLS 256

/* https://en.wikipedia.org/wiki/Letter_frequency */
static float letter_freq [] = {0.08167,0.01492,0.02782,0.04253,0.12702,0.02228,0.02015,0.06094,0.06966,0.00153,0.00772,0.04025,0.02406,0.06749,0.07507,0.01929,0.00095,0.05987,0.06327,0.09056,0.02758,0.00978,0.02361,0.00150,0.01974,0.00074};

/* Cracking single byte XOR cipher */
/* Decrypting the cipher using all keys (byte - 256 options - ascii table). Than scoring each plaintext by calculating the distance between the observed probability of a letter and the letter frequency in the English language. Also, no observation of a letter is penalized - for correct results should not be 0, preferbly 1. Another scoring method is availble - the key that generates the highest count of letters is chosen. User can choose scoringm method by setting distance_scoring. 0 - for distance scoring, else for maximum letters count.
 */

BYTE *break_cipher(const char *ct, int penalty, int distance_scoring ){
    
    float sum, score[ASCII_SYMBOLS] = {0},letter_freq_cp[ASCII_SYMBOLS][ENGLISH_LETTERS]={0};
    unsigned int nonzero, max_letters_key, min_distance_key = 0;
    unsigned int total_num_letters[ASCII_SYMBOLS];
    int key,col,xor;
    unsigned long str_len = strlen(ct);
    
    /* Allocating byte array for convertion between hex string to byte array*/
    BYTE *byteArr = (BYTE *)malloc(str_len/2);
    if (byteArr == NULL){
        free(byteArr);
        printf("Error allocating memory!\n");
    }
    
    /* Converting hex string to byte array */
    hexStr2byteArr(ct, str_len , byteArr);
   
    /* Decrypting the cipher with each ascii symbok and counting the letter frequncy for each key */
    max_letters_key = 0;
    for ( key = 0; key < ASCII_SYMBOLS ; key++ ){
        total_num_letters[key]=0;
        for ( int i = 0 ; i < str_len/2 ; i++){
            col = byteArr[i]^key;           // decrypting
            if ( col >= 'a' && col <= 'z'){
                letter_freq_cp[key][col - 'a']++;   // counting the letter frequncy
                total_num_letters[key]++;   // counting the amount of letters
            } else if ( col >= 'A' && col <= 'Z') {
                letter_freq_cp[key][col - 'A']++;   // not case sensitive
                total_num_letters[key]++;
            }
        }
        
        if (total_num_letters[max_letters_key] < total_num_letters[key])
            max_letters_key=key;    // key for highest count of letters
        
        sum = 0;
        nonzero=0;
        for ( int i = 0; i < ENGLISH_LETTERS; i++ ){
            if ( letter_freq_cp[key][i] != 0 ){
                sum += sqrt(pow(((2*letter_freq_cp[key][i])/str_len) - letter_freq[i],2)); // calculating the distance between two probabilities.
            } else {
                sum+= penalty;  // adding penalty for 0 observations
            }
        }
        
        score[key] = sum;
        if (score[key] < score[min_distance_key])
            min_distance_key = key; // minimal probability distance key
    }
    
    if (distance_scoring){  // Scoring method choise
        xor = min_distance_key;
    } else {
        xor = max_letters_key;
    }
    
    for ( int i = 0 ; i< str_len; i++)  // Decrypting with the chosen key
        byteArr[i] = byteArr[i] ^ xor;
        
    return byteArr;
}