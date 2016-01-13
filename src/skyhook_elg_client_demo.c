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

/********************************************************************
                    Skyhook ELG Client Demo
This program demonstrates the neccessary steps needed to perform a
location request/response and how to setup the communication to/from
the Embedded Location Gateway (ELG).
It is a Linux based program, but the elements can be easily ported to
an embeddded C project.
*********************************************************************/

#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>
#include "sky_types.h"
#include "sky_protocol_client_1.h"
#include "sky_util.h"
#include "sky_crypt.h"

/* url to skyhook ELG server */
#define SKYHOOK_ELG_SERVER_URL "elg.skyhookwireless.com"

/* Skyhook ELG server port */
#define SKYHOOK_ELG_SERVER_PORT 9755

/* userid provided by Skyhook */
/* replace this with yours */
#define USERID 11111

/*  AES key provided by Skyhook */
/* replace this with yours */
/* store the key in a secure area */
#define AES_KEY {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01}

int main(int argc, char**argv)
{
    /* create buffer to hold packet */
    unsigned char buff[1024];

    /* initialize the random number generator */
    srand((unsigned int)time(NULL));

    /* query and set the device MAC */
    /* use the wifi chip MAC address */
    /* here we just set it to a constant */
    unsigned char device_MAC[] = {0xCA,0xFE,0xBA,0xBE,0xCA,0xFE};

    /* allocate buffer
       memory allocation can be dynamic or static
       make sure to set the ap_count to the actual value of the wifi scan count
       but limit to what fits into the buffer
    */

    const int ap_count = 4;
    struct ap_t aps[ap_count];

   /* load wifi scan result */
   /* for demo purposes we assign them manually */
    aps[0].rssi = -50;
    aps[0].MAC[0] = 0x00;
    aps[0].MAC[1] = 0x0C;
    aps[0].MAC[2] = 0x41;
    aps[0].MAC[3] = 0x82;
    aps[0].MAC[4] = 0xD8;
    aps[0].MAC[5] = 0x8C;

    aps[1].rssi = -50;
    aps[1].MAC[0] = 0x00;
    aps[1].MAC[1] = 0x04;
    aps[1].MAC[2] = 0x5A;
    aps[1].MAC[3] = 0x0E;
    aps[1].MAC[4] = 0x27;
    aps[1].MAC[5] = 0x2B;

    aps[2].rssi = -50;
    aps[2].MAC[0] = 0x00;
    aps[2].MAC[1] = 0x01;
    aps[2].MAC[2] = 0x22;
    aps[2].MAC[3] = 0x55;
    aps[2].MAC[4] = 0xA5;
    aps[2].MAC[5] = 0xA3;

    aps[3].rssi = -50;
    aps[3].MAC[0] = 0x00;
    aps[3].MAC[1] = 0x0C;
    aps[3].MAC[2] = 0x41;
    aps[3].MAC[3] = 0xA2;
    aps[3].MAC[4] = 0xDF;
    aps[3].MAC[5] = 0x52;

    /* set userid and AES key */
    struct aes_key_t key = {USERID, AES_KEY};

    /* create location request */
    struct location_req_t rq;
    rq.key = &key; // assign key

    // copy device mac to location rq struct
    memcpy(rq.MAC, device_MAC, sizeof(rq.MAC));

    /* set protocol version */
    rq.protocol = SKY_PROTOCOL_VERSION;

    /* set location request type */
    /* LOCATION_RQ will return latitude, longitude and hpe
       LOCATION_RQ_ADDR will also include street address lookup */

    //rq.payload_type = LOCATION_RQ; // simple location request
    rq.payload_type = LOCATION_RQ_ADDR; // full address lookup
    rq.version = SKY_SOFTWARE_VERSION; // skyhook client library version
    rq.ap_count = ap_count & 0xFF; // set the number of scanned access points
    rq.aps = aps; // assign aps

    // in this demo we are not using cell, ble or gps
    // zero counts
    rq.ble_count = 0;
    rq.cell_count = 0;
    rq.gps_count = 0;

    /****************************************
        SKYHOOK provided source code
     ****************************************/
    /* encode rq data into buffer */
    int cnt = sky_encode_req_bin_1(buff, sizeof(buff), &rq);

    if (cnt == -1)
    {
        perror("failed to encode request\n");
        exit(-1);
    }

    /* print out the encoded buffer before encryption */
    printf("bytes: %d\n", cnt);
    puts("\n------ encoded packet -------");
    print_buff(buff, cnt);
    puts("---------------------\n");

    /* encrypt buffer, use hardware encryption when available */
    int r = sky_aes_encrypt(buff + REQUEST_HEAD_SIZE_1, cnt - REQUEST_HEAD_SIZE_1, key.aes_key, buff + REQUEST_IV_OFFSET_1);

    if (r == -1)
    {
        perror("failed to encrypt");
        exit(-1);
    }

    puts("\n------ encrypted packet to be sent to skyhook elg server -------");
    print_buff(buff, cnt);
    puts("---------------------\n");

    /*********************************************
        Internet transaction handled by user
     ********************************************/
    /* this is a sample linux code demonstrating how to send
       data through tcp socket to ELG server.
       on embedded devices use the cell modem or other means
       of connection to the interent */

    /* SETUP SOCKET */
    struct sockaddr_in serv_addr;

    // fd handler for tcp socket and connection
    int sockfd;

    // clear server address
    memset(&serv_addr, 0, sizeof(serv_addr));

    char ipaddr[16]; // buffer large enough for ipv6

    // lookup server ip address
    int hstnm = hostname_to_ip(SKYHOOK_ELG_SERVER_URL, ipaddr);

    if (hstnm != 0)
    {
        puts("Could not resolve host");
        exit(-1);
    }

    printf("Resolved host: %s\n", SKYHOOK_ELG_SERVER_URL);
    printf("server ip: %s port: %d\n", ipaddr, SKYHOOK_ELG_SERVER_PORT);

    // init server address struct and set ip and port
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SKYHOOK_ELG_SERVER_PORT);
    serv_addr.sin_addr.s_addr = inet_addr(ipaddr);

    // open socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("cannot open socket");
        exit(-1);
    }

    /* setup connection timeout */
    struct timeval tv;

    tv.tv_sec = 10;  /* Secs Timeout */
    tv.tv_usec = 0;  // Not zeroing this can cause errors

    /* setup connection timeout */
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)))
    {
        perror("setsockopt failed");
        exit(-1);
    }

    /* start connection */
    int res = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    if (res < 0)
    {
        close(sockfd);
        perror("connect to server failed");
        exit(-1);
    }

    /* send data to the server */
    res = send(sockfd, buff, (size_t)cnt, 0);

    if (res != cnt)
    {
        close(sockfd);
        perror("send() sent a different number of bytes than expected");
        exit(-1);
    }

    printf("total bytes sent to server %d\n", res);

    // clear the buffer
    memset(buff, 0, sizeof(buff));

    /* wait for tcp response */
    cnt = recv(sockfd, buff, sizeof(buff), 0);

    if (cnt == 0) // connection closed or timeout
    {
        errno = ETIMEDOUT;
        close(sockfd);
        perror("connection closed (timeout?)");
        exit(-1);
    }
    else if (cnt < 0) // error in receiving
    {
        close(sockfd);
        perror("recv failed");
        exit(-1);
    }

    // print encrypted received buffer
    printf("total received bytes: %d\n", cnt);
    puts("\n------ recv packet -------");
    print_buff(buff, cnt);
    puts("---------------------\n");

    close(sockfd);

    // received a server error (most likely server overload)
    if (buff[0] == SERVER_ERR)
    {
        unsigned int err = buff[1] | (buff[2] << 8);
        printf("SERVER ERROR %u\n", err);
        exit(-1);
    }

    // prepare location response struct
    struct location_resp_t resp;
    memset(&resp.location_ex, 0, sizeof(resp.location_ex)); // clear the values
    resp.key = &key; // assign decryption key

    /****************************************
        SKYHOOK provided source code
     ****************************************/
    /* decrypt the received packet
       this can be replaced with hardware encryption when available */
    if (sky_aes_decrypt(buff + RESPONSE_HEAD_SIZE_1, cnt - RESPONSE_HEAD_SIZE_1, key.aes_key, buff + RESPONSE_IV_OFFSET_1) != 0)
    {
        perror("failed to decrypt response");
        exit(-1);
    }

    // print decrypted packet
    puts("\n------ decrypted recv packet -------");
    print_buff(buff, cnt);
    puts("---------------------\n");

    /* decode packet */
    /* location response will be decoded to resp */
    res = sky_decode_resp_bin_1(buff, sizeof(buff), cnt, &resp);

    if (res == -1)
    {
        perror("failed to decode response");
        exit(-1);
    }

    // print location response
    puts("--------------");
    puts("PARSED RESPONSE");
    puts("--------------");
    print_location_resp(&resp);

    return 0;
}
