//
//  single_byte_xor_cipher.h
//  matasano_crypto_set1
//
//  Created by Evgeni Ron Overchick on 5/7/16.
//  Copyright © 2016 Evgeni Ron Shtrakh. All rights reserved.
//

#ifndef single_byte_xor_cipher_h
#define single_byte_xor_cipher_h

#include <stdio.h>
#include "crypto_utils.h"

#define PENALTY 1
#define DISTANCE_SCORING 0

u_int8 *break_cipher(const char *ct, int penalty, int distance_scoring );

#endif /* single_byte_xor_cipher_h */
