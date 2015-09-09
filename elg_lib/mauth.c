/*
 * Copyright 2015-present Skyhook Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mauth.h"

#define IN_PAD 0x36
#define OUT_PAD 0x5C
#define BLOCK_SIZE 64
#define OUTPUT_SIZE 32
#define MAX_HASH_SIZE 4

typedef struct key_io {
    char k_str_in[BLOCK_SIZE];
    char k_str_out[BLOCK_SIZE];
} key_io;


void hmac(char *k, int k_len, char *m, unsigned char *ciph)
{
    key_io keys;
    memcpy(&keys, k, BLOCK_SIZE);

    keys.k_str_in[BLOCK_SIZE - 1] = '\0';
    keys.k_str_out[BLOCK_SIZE - 1] = '\0';

    pad_array_with(IN_PAD, keys.k_str_in, strlen(keys.k_str_in));
    pad_array_with(OUT_PAD, keys.k_str_out, strlen(keys.k_str_out));

    //MUST BE BLOCK SIZE (size of data element)
    //Compiler differences will init memory differently and things WILL break.
    char strt_str[BLOCK_SIZE + MESSAGE_SIZE];

    unsigned char in_ciph[BLOCK_SIZE];
    sha((unsigned char *)memcpy(strt_str, m, MESSAGE_SIZE), in_ciph);

    char h_in[BLOCK_SIZE + MESSAGE_SIZE];
    memcpy(h_in,  keys.k_str_out, BLOCK_SIZE); memcpy(h_in + BLOCK_SIZE, (char *) in_ciph, BLOCK_SIZE);
    sha((unsigned char *)h_in, ciph);
}

void pad_array_with(char pad, char *array, size_t sz)
{
    int i;
    for (i = sz; i-- > 0; )
    {
        array[i] = array[i] ^ pad;
    }
}

void sha(unsigned char *clrtext, unsigned char ciph[])
{
    SHA256_CTX ctx;

    hmac256_init(&ctx);
    hmac256_update(&ctx, clrtext, strlen((char *) clrtext));
    hmac256_final(&ctx, ciph);
}
