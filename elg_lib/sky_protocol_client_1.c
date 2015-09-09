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
#include <errno.h>
#include <inttypes.h>
#include "sky_types.h"
#include "sky_protocol_client_1.h"
#include "sky_crypt.h"

int sky_encode_req_bin_1(unsigned char *buff, int buff_len, struct location_req_t *creq)
{
    int crypt_len = 8; // payload type 1 + client softw version 1 + client mac 6
    // timestamp 6
    int pad_len;
    int packet_len = REQUEST_HEAD_SIZE_1;
    
    if (creq->payload_type != LOCATION_RQ &&
        creq->payload_type != LOCATION_RQ_ADDR)
    {
        #ifdef DEBUG
        fprintf(stderr, "sky_encode_req_bin: unknown payload type %d\n", creq->payload_type);
        #endif
        return -1;
    }

    if (buff_len < REQUEST_HEAD_SIZE_1 + 8)
    {
        #ifdef DEBUG
        perror("buffer too small");
        #endif
        return -1;
    }
    
    unsigned char acnt = creq->ap_count;
    unsigned char bcnt = creq->ble_count;
    unsigned char ccnt = creq->cell_count;
    unsigned char gcnt = creq->gps_count;

    if (acnt > 0) crypt_len += acnt * (int)sizeof(struct ap_t) + 2;
    if (bcnt > 0) crypt_len += bcnt * (int)sizeof(struct ble_t) + 2;
    if (gcnt > 0) crypt_len += gcnt * (int)sizeof(struct gps_t) + 2;

    if (ccnt > 0)
    {
        int sz;

        switch(creq->cell_type)
        {
            case DATA_TYPE_GSM: sz = (int)sizeof(struct gsm_t); break;
            case DATA_TYPE_CDMA: sz = (int)sizeof(struct cdma_t); break;
            case DATA_TYPE_UMTS: sz = (int)sizeof(struct umts_t); break;
            case DATA_TYPE_LTE: sz = (int)sizeof(struct lte_t); break;
            default: return -1;
        }

        crypt_len += ccnt * sz + 2;
    }
    
    pad_len = 16 - (crypt_len & 0X0F);
    if (pad_len < 2) pad_len += 16; // we need to add the 2 verification fields

    crypt_len += pad_len;
    packet_len += crypt_len;

    if (packet_len > buff_len)
    {
        #ifdef DEBUG
        perror("buffer too small");
        #endif
        return -1;
    }
    
    unsigned char *p = buff;
    *p++ = creq->protocol; // 0
    
    memcpy(p, &creq->key->userid, sizeof(creq->key->userid)); // 1 - 4
    p += sizeof(creq->key->userid); // move pinter

    *p++ = (unsigned char)(packet_len & 0xFF); // 5
    *p++ = (unsigned char)(packet_len >> 8 & 0xFF); // 6

    // 16 byte initialization vector
    sky_gen_iv(p); // 7 - 22
    p += 16;
    
    *p++ = creq->version; // client firmware version
    memcpy(p, creq->MAC, 6);
    p += 6;

    *p++ = creq->payload_type;
    
    int sz = 0;
    
    if (creq->ap_count > 0)
    {
        *p++ = DATA_TYPE_AP;
        *p++ = acnt;
        sz = (int)sizeof(struct ap_t) * acnt;
        memcpy(p, creq->aps, (size_t)sz);
        p+= sz;
    }

    if (creq->ble_count > 0)
    {
        *p++ = DATA_TYPE_BLE;
        *p++ = bcnt;
        sz = (int)sizeof(struct ble_t) * bcnt;
        memcpy(p, creq->bles, (size_t)sz);
        p+= sz;
    }

    if (creq->cell_count > 0)
    {
        *p++ = creq->cell_type;
        *p++ = ccnt;

        switch (creq->cell_type)
        {
            case DATA_TYPE_GSM:
                sz = (int)sizeof(struct gsm_t) * ccnt;
                memcpy(p, creq->gsm, (size_t)sz);
                break;

            case DATA_TYPE_LTE:
                sz = (int)sizeof(struct lte_t) * ccnt;
                memcpy(p, creq->lte, (size_t)sz);
                break;

            case DATA_TYPE_CDMA:
                sz = (int)sizeof(struct cdma_t) * ccnt;
                memcpy(p, creq->cdma, (size_t)sz);
                break;   

            case DATA_TYPE_UMTS:
                sz = (int)sizeof(struct umts_t) * ccnt;
                memcpy(p, creq->umts, (size_t)sz);
                break;

            default: return -1;
        }  

        p+= sz;
    }

    if (creq->gps_count > 0)
    {
        *p++ = DATA_TYPE_GPS;
        *p++ = gcnt;
        sz = (int)sizeof(struct gps_t) * gcnt;
        memcpy(p, creq->gps, (size_t)sz);
        p+= sz;
    }

    if (pad_len > 2)
    {
        memset(p, SKY_PAD_CHAR, (size_t)pad_len - 2);
    }

    p = buff + REQUEST_HEAD_SIZE_1 + crypt_len - 2;

    uint16_t chks = fletcher16(buff + REQUEST_HEAD_SIZE_1, crypt_len - 2); // skip checks

    *p++ = chks & 0xFF;
    *p = (chks >> 8) & 0xFF;

    return packet_len;
}

int sky_decode_resp_bin_1(unsigned char *buff, int buff_len, int data_len, struct location_resp_t *cresp)
{
    if (buff_len < RESPONSE_HEAD_SIZE_1 + 8 || buff_len < data_len) // have at least min packet len
    {   
        errno = ENOBUFS;
        #ifdef DEBUG
        perror("buffer too small");
        #endif
        return -1; // buffer too small
    }

    cresp->protocol = buff[0]; // protocol version
    int packet_size = buff[1] | buff[2] << 8;

    if (packet_size > data_len) packet_size = data_len;
    int crypt_size = packet_size - RESPONSE_HEAD_SIZE_1;

    // wrong packet size indicated
    if (packet_size > buff_len || (crypt_size & 0x0F)) // has to be 16 byte blocks
    {
        #ifdef DEBUG
        perror("wrong packet size");
        #endif
        return -1;
    }

    uint16_t chks = fletcher16(buff + RESPONSE_HEAD_SIZE_1, crypt_size - 2); // skip last 2 bytes

    if (buff[packet_size - 2] != (chks & 0XFF) || 
        buff[packet_size - 1] != (chks >> 8))
    {
        #ifdef DEBUG
        perror("decoding failed: wrong checks byte");
        #endif
        return -1;
    }

    unsigned char *p = buff + RESPONSE_HEAD_SIZE_1;

    cresp->version = *p++;
    cresp->timestamp = 0;
    memcpy(&cresp->timestamp, p, 6);
    p += 6;
    
    cresp->payload_type = *p++;

    if (cresp->payload_type == LOCATION_RQ)
    {
        memcpy(&cresp->location, p, LOCATION_T_SIZE);
        return 0;
    }
    else if (cresp->payload_type == LOCATION_RQ_ADDR)
    {
        memcpy(&cresp->location, p, LOCATION_T_SIZE);
        p += LOCATION_T_SIZE;

        int data_type_cnt = 13; // number of data type expected
        crypt_size -= (sizeof(cresp->location) + 5);

        while(data_type_cnt > 0 && crypt_size > 0)
        {
            unsigned char dtype = *p++; // first is the data type

            int sz;

            if (dtype == DATA_TYPE_IPV4) 
            {
                sz = 4;
                crypt_size--;
            }
            else if (dtype == DATA_TYPE_IPV6) 
            {
                sz = 16;
                crypt_size--;
            }
            else 
            {
                sz = (int)*p++; // next is size
                crypt_size -= 2;
            }
            
            crypt_size -= sz;

            switch (dtype)
            {
                case DATA_TYPE_STREET_NUM:
                    cresp->location_ex.street_num_len = sz;
                    cresp->location_ex.street_num = (char *)p;
                    data_type_cnt--;
                    break;

                case DATA_TYPE_ADDRESS:
                    cresp->location_ex.address_len = sz;
                    cresp->location_ex.address = (char *)p;
                    data_type_cnt--;
                    break;

                case DATA_TYPE_CITY:
                    cresp->location_ex.city_len = sz;
                    cresp->location_ex.city = (char *)p;
                    data_type_cnt--;
                    break;

                case DATA_TYPE_STATE:
                    cresp->location_ex.state_len = sz;
                    cresp->location_ex.state = (char *)p;
                    data_type_cnt--;
                    break;

                case DATA_TYPE_STATE_CODE:
                    cresp->location_ex.state_code_len = sz;
                    cresp->location_ex.state_code = (char *)p;
                    data_type_cnt--;
                    break;

                case DATA_TYPE_METRO1:
                    cresp->location_ex.metro1_len = sz;
                    cresp->location_ex.metro1 = (char *)p;
                    data_type_cnt--;
                    break;

                case DATA_TYPE_METRO2:
                    cresp->location_ex.metro2_len = sz;
                    cresp->location_ex.metro2 = (char *)p;
                    data_type_cnt--;
                    break;

                case DATA_TYPE_POSTAL_CODE:
                    cresp->location_ex.postal_code_len = sz;
                    cresp->location_ex.postal_code = (char *)p;
                    data_type_cnt--;
                    break;

                case DATA_TYPE_COUNTY:
                    cresp->location_ex.county_len = sz;
                    cresp->location_ex.county = (char *)p;
                    data_type_cnt--;
                    break;

                case DATA_TYPE_COUNTRY:
                    cresp->location_ex.country_len = sz;
                    cresp->location_ex.country = (char *)p;
                    data_type_cnt--;
                    break;

                case DATA_TYPE_COUNTRY_CODE:
                    cresp->location_ex.country_code_len = sz;
                    cresp->location_ex.country_code = (char *)p;
                    data_type_cnt--;
                    break;

                case DATA_TYPE_IPV4:
                    cresp->location_ex.ip_type = DATA_TYPE_IPV4;
                    memcpy(cresp->location_ex.ipaddr, p, 4);
                    data_type_cnt--;
                    break;

                case DATA_TYPE_IPV6:
                    cresp->location_ex.ip_type = DATA_TYPE_IPV6;
                    memcpy(cresp->location_ex.ipaddr, p, 16);
                    data_type_cnt--;
                    break;

                case DATA_TYPE_DIST_POINT:
                    memcpy(&cresp->location_ex.distance_to_point, p, sizeof(float));
                    data_type_cnt--;
                    break;

                default:// we are at the end quit
                    data_type_cnt = 0;
            }
            p += sz;
        }
    }
    
    return 0;
}
