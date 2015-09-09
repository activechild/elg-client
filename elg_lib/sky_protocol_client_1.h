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

/***********************************************
    BINARY REQUEST PROTOCOL FORMAT
************************************************
    0  - protocol version 0
    1  - client id 0
    2  - client id 1
    3  - client id 2
    4  - client id 3
    5  - entire payload length 0 - LSB count includes byte 0
    6  - entire payload length 1 - MSB
    7  - iv 0
    8  - iv 1
    9  - iv 2
    10 - iv 3
    11 - iv 4
    12 - iv 5
    13 - iv 6
    14 - iv 7
    15 - iv 8
    16 - iv 9
    17 - iv 10
    18 - iv 11
    19 - iv 12
    20 - iv 13
    21 - iv 14
    22 - iv 15
    --- encrypted after this ---
    23 - client software version
    24 - client MAC 0
    25 - client MAC 1
    26 - client MAC 2
    27 - client MAC 3
    28 - clinet MAC 4
    29 - clinet MAC 5
    30 - payload type -- e.g. location request
    -------------------
    payload data can be out of order (type,count/size,data)
    31 - data type -- refers to DATA_TYPE enum and struct
    32 - data type count -- this a the number of structs (0 - 255)
    33 - data... memcopied data struct (ap, cell, ble, gps)
    ...
    n - 2 verify 0 fletcher 16
    n - 1 verify 1 fletcher 16
*************************************************/

/***********************************************
    BINARY RESPONSE PROTOCOL FORMAT
************************************************
    0  - protocol version
    1  - entire payload length 0 - LSB count includes byte 0
    2  - entire payload length 1 - MSB
    3  - iv 0
    4  - iv 1
    5  - iv 2
    6  - iv 3
    7  - iv 4
    8  - iv 5
    9  - iv 6
    10 - iv 7
    11 - iv 8
    12 - iv 9
    13 - iv 10
    14 - iv 11
    15 - iv 12
    16 - iv 13
    17 - iv 14
    18 - iv 15
    --- encrypted after this ---
    19 - server software version
    20 - timestamp 0
    21 - timestamp 1
    22 - timestamp 2
    23 - timestamp 3
    24 - timestamp 4
    25 - timestamp 5
    26 - payload type -- e.g. location request
    -------------------
    payload data can be out of order (type,count/size,data)
    27 - data type -- refers to DATA_TYPE enum and struct
    28 - data type count -- this a the number of structs (0 - 255)
    29 - data... memcopied data struct (ap, cell, ble, gps)
    ...
    n - 2 verify 0 fletcher 16
    n - 1 verify 1 fletcher 16
*************************************************/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SKY_PROTOCOL_CLIENT_1_H
#define SKY_PROTOCOL_CLIENT_1_H

#define SKY_SOFTWARE_VERSION    1
#define SKY_PROTOCOL_VERSION    1

#define SKY_PAD_CHAR            0xAA
#define SERVER_ERR              0xFF

#define REQUEST_HEAD_SIZE_1     23
#define REQUEST_IV_OFFSET_1     7
#define RESPONSE_HEAD_SIZE_1    19
#define RESPONSE_IV_OFFSET_1    3

#ifndef ENOBUFS
#define ENOBUFS (ENOMEM)
#endif

// sent by the client to the server
/* encodes the request struct into binary formatted packet */
// returns the packet len or -1 when fails
int sky_encode_req_bin_1(unsigned char *buff, int buff_len, struct location_req_t *creq);

// received by the client from the server
/* decodes the binary data and the result is in the location_resp_t struct */
int sky_decode_resp_bin_1(unsigned char *buff, int buff_len, int data_len, struct location_resp_t *cresp);

#endif

#ifdef __cplusplus
}
#endif
