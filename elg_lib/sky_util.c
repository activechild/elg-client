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
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include "sky_util.h"
#include "sky_types.h"

void print_s(char *buff, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        printf("%c", buff[i]);
    }
    printf("\n");
}

void print_buff(unsigned char *buff, int len)
{
    int i;
    int j = 0;

    for (i = 0; i < len; i++)
    {
        printf("%02X ", buff[i] & 0xFF);

        if (++j > 15)
        {
            j = 0;
            printf("\n");
        }
    }
    printf("\n");
}

void print_ip(unsigned char *ip, unsigned char ip_type)
{
    if (ip == NULL) return;

    int i;

    if (ip_type == DATA_TYPE_IPV6)
    {
        char z = 0;

        for (i = 0; i < 8; i++)
        {
            if (ip[i] == 0 && ip[i+1] == 0)
            {
                z = 1;
                continue;
            }

            if (z) printf(":");
            printf("%02x",ip[i]);
            printf("%02x",ip[i+1]);
            printf(":");
            z = 0;
        }
    }
    else
    {
        for (i = 0; i < 4; i++)
        {
            printf("%d",ip[i]);
            if (i < 3) printf(".");
        }
    }
    printf("\n");
}

int hostname_to_ip(char * hostname , char* ip)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;

    if ( (he = gethostbyname( hostname ) ) == NULL)
    {
        // get the host info
        herror("gethostbyname");
        return 1;
    }

    addr_list = (struct in_addr **) he->h_addr_list;

    for(i = 0; addr_list[i] != NULL; i++)
    {
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }

    return 1;
}

void print_location_resp(struct location_resp_t *cr)
{
    printf("\n");
    printf("timestamp: %" PRIu64 "\n", cr->timestamp);
    printf("protocol: %d\n", cr->protocol);
    printf("server version: %d\n", cr->version);
    printf("payload type no: %d\n", cr->payload_type);

    // http codes
    if (cr->payload_type < HTTP_UNKNOWN && cr->payload_type >= HTTP_200)
    {
        int err;
        if (cr->payload_type > HTTP_505) err = HTTP_UNKNOWN;
        else if (cr->payload_type >= HTTP_500) err = cr->payload_type - HTTP_500 + 500;
        else if (cr->payload_type > HTTP_417) err = HTTP_UNKNOWN;
        else if (cr->payload_type >= HTTP_400) err = cr->payload_type - HTTP_400 + 400;
        else if (cr->payload_type > HTTP_307) err = HTTP_UNKNOWN;
        else if (cr->payload_type >= HTTP_300) err = cr->payload_type - HTTP_300 + 300;
        else if (cr->payload_type > HTTP_206) err = HTTP_UNKNOWN;
        else if (cr->payload_type >= HTTP_200) err = cr->payload_type - HTTP_200 + 200;
        else err = HTTP_UNKNOWN;

        printf("HTTP %d\n", err);
    }
    else
    {
        switch (cr->payload_type)
        {
            case PAYLOAD_ERROR: puts("PAYLOAD_ERROR"); break;
            case PAYLOAD_API_ERROR: puts("PAYLOAD_API_ERROR"); break;
            case SERVER_ERROR: puts("SERVER_ERROR"); break;
            case LOCATION_RQ_ERROR: puts("LOCATION_RQ_ERROR"); break;
            case PAYLOAD_NONE: puts("PAYLOAD_NONE"); break;
            case PROBE_REQUEST: puts("PROBE_REQUEST"); break;
            case DECODE_BIN_FAILED: puts("DECODE_BIN_FAILED"); break;
            case ENCODE_BIN_FAILED: puts("ENCODE_BIN_FAILED"); break;
            case DECRYPT_BIN_FAILED: puts("DECRYPT_BIN_FAILED"); break;
            case ENCRYPT_BIN_FAILED: puts("ENCRYPT_BIN_FAILED"); break;
            case ENCODE_XML_FAILED: puts("ENCODE_XML_FAILED"); break;
            case DECODE_XML_FAILED: puts("DECODE_XML_FAILED"); break;
            case SOCKET_FAILED : puts("SOCKET_FAILED "); break;
            case SOCKET_WRITE_FAILED: puts("SOCKET_WRITE_FAILED"); break;
            case SOCKET_READ_FAILED: puts("SOCKET_READ_FAILED"); break;
            case SOCKET_TIMEOUT_FAILED: puts("SOCKET_TIMEOUT_FAILED"); break;
            case CREATE_META_FAILED: puts("CREATE_META_FAILED"); break;
            case HTTP_UNKNOWN: puts("HTTP_UNKNOWN"); break;
        }
    }

    if (cr->payload_type != LOCATION_RQ &&
        cr->payload_type != LOCATION_RQ_ADDR) return;

    puts("LOCATION_RQ");
    printf("latitude: %f\n", cr->location.lat);
    printf("longitude: %f\n", cr->location.lon);
    printf("hpe: %f\n", cr->location.hpe);

    if (cr->payload_type == LOCATION_RQ_ADDR)
    {
        puts("LOCATION_RQ_ADDR");
        printf("distance_to_point: %f\n", cr->location_ex.distance_to_point);
        printf("street num: "); print_s(cr->location_ex.street_num, cr->location_ex.street_num_len);
        printf("address: "); print_s(cr->location_ex.address, cr->location_ex.address_len);
        printf("city: "); print_s(cr->location_ex.city, cr->location_ex.city_len);
        printf("state: "); print_s(cr->location_ex.state, cr->location_ex.state_len);
        printf("state code: "); print_s(cr->location_ex.state_code, cr->location_ex.state_code_len);
        printf("postal code: "); print_s(cr->location_ex.postal_code, cr->location_ex.postal_code_len);
        printf("county: "); print_s(cr->location_ex.county, cr->location_ex.county_len);
        printf("country: "); print_s(cr->location_ex.country, cr->location_ex.country_len);
        printf("country code: "); print_s(cr->location_ex.country_code, cr->location_ex.country_code_len);
        printf("metro1: "); print_s(cr->location_ex.metro1, cr->location_ex.metro1_len);
        printf("metro2: "); print_s(cr->location_ex.metro2, cr->location_ex.metro2_len);
        printf("ip: "); print_ip(cr->location_ex.ipaddr, cr->location_ex.ip_type);
    }
}


