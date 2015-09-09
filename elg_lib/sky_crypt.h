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

#ifndef SKY_CRYPT_H
#define SKY_CRYPT_H

#include "sky_types.h"

/* generate initialization vector */
void sky_gen_iv(unsigned char *iv);

/* encrypt data */
int sky_aes_encrypt(unsigned char *data, uint32_t data_len, unsigned char *key, unsigned char *iv);

/* decrypt data */
int sky_aes_decrypt(unsigned char *data, uint32_t data_len, unsigned char *key, unsigned char *iv);

/* generate 2 byte checksum */
uint16_t fletcher16(uint8_t const *buff, int buff_len);

#endif
