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

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "../HMAC/hmac256.h"

#define KEY_SIZE 64
#define MESSAGE_SIZE 64

void sha(unsigned char *clrtext, unsigned char *ciph);
void hmac(char *k, int k_len, char *m, unsigned char *ciph);
void pad_array_with(char pad, char *array, size_t sz);
bool check(char *k, int k_len, char *m, unsigned char *mac);
