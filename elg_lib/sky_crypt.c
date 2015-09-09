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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sky_crypt.h"
#include "aes.h"
#include "mauth.h"

// iv must be 16 byte long
void sky_gen_iv(unsigned char *iv)
{
    char key[KEY_SIZE];
    char mes[MESSAGE_SIZE];
    int i;
    for(i = 0; i < KEY_SIZE; i++){
        key[i] = rand() % 256;
    }
    for(i = 0; i < MESSAGE_SIZE; i++){
        mes[i] = rand() % 256;
    }

    hmac(key, KEY_SIZE, mes, iv);
}

// iv and key must be 16 byte long
int sky_aes_encrypt(unsigned char *data, uint32_t data_len, unsigned char *key, unsigned char *iv)
{
    if (data_len & 0x0F)
    {
        perror("non 16 byte blocks");
        return -1;
    }

    unsigned char output[data_len];
    AES128_CBC_encrypt_buffer(output, data, data_len, key, iv);
    memcpy(data, output, data_len);

    return 0;
}

// iv and key must be 16 byte long
int sky_aes_decrypt(unsigned char *data, uint32_t data_len, unsigned char *key, unsigned char *iv)
{
    if (data_len & 0x0F)
    {
        perror("non 16 byte blocks");
        return -1;
    }

    unsigned char output[data_len];
    AES128_CBC_decrypt_buffer(output, data, data_len, key, iv);
    memcpy(data, output, data_len);

    return 0;
}

// checksum
uint16_t fletcher16(uint8_t const *buff, int buff_len)
{
    uint16_t s1, s2;
    s1 = s2 = 0xFF;

    while (buff_len) 
    {
        int len = buff_len > 20 ? 20 : buff_len;

        buff_len -= len;

        do 
        {
            s2 += s1 += *buff++;
        } 
        while (--len);

        s1 = (s1 & 0xFF) + (s1 >> 8);
        s2 = (s2 & 0xFF) + (s2 >> 8);
    }

    /* Second reduction step to reduce sums to 8 bits */
    s1 = (s1 & 0xFF) + (s1 >> 8);
    s2 = (s2 & 0xFF) + (s2 >> 8);

    return s2 << 8 | s1;
}

