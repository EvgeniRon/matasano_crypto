//
//  hex2base64.h
//  matasano_crypto_set1
//
//  Created by Evgeni Ron Overchick on 4/26/16.
//  Copyright © 2016 Evgeni Ron Shtrakh. All rights reserved.
//

#ifndef hex2base64_h
#define hex2base64_h

#include <stdio.h>
#include <stdlib.h>

typedef unsigned char BYTE;
BYTE *hex2base64(const char *str, unsigned int str_len);



#endif /* hex2base64_h */
