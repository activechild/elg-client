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

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SKY_TYPES_H
#define SKY_TYPES_H

#include <inttypes.h>

// server error
#define SERVER_ERR 0xFF

// server cannot handle more than preset process limit using http error code numbers for simplicity
#define SERVICE_UNAVAILABLE_503 {SERVER_ERR, 0xF7, 0x01}
#define PROTOCOL_NOT_ACCEPTABLE_406 {SERVER_ERR, 0x96, 0x01}

// stored in one byte
enum SKY_DATA_TYPE
{
    DATA_TYPE_NONE          = 0, // uninitialized
    DATA_TYPE_AP            = 1, // access point
    DATA_TYPE_GPS           = 2, // gps
    DATA_TYPE_GSM           = 3, // cell gsm
    DATA_TYPE_CDMA          = 4, // cell cdma
    DATA_TYPE_UMTS          = 5, // cell umts
    DATA_TYPE_LTE           = 6, // cell lte
    DATA_TYPE_BLE           = 7, // bluetooth
    DATA_TYPE_STREET_NUM    = 8,
    DATA_TYPE_ADDRESS       = 9,
    DATA_TYPE_CITY          = 10,
    DATA_TYPE_STATE         = 11,
    DATA_TYPE_STATE_CODE    = 12,
    DATA_TYPE_METRO1        = 13,
    DATA_TYPE_METRO2        = 14,
    DATA_TYPE_POSTAL_CODE   = 15,
    DATA_TYPE_COUNTY        = 16,
    DATA_TYPE_COUNTRY       = 17,
    DATA_TYPE_COUNTRY_CODE  = 18,
    DATA_TYPE_DIST_POINT    = 19,
    DATA_TYPE_IPV4          = 20, // ipv4 address
    DATA_TYPE_IPV6          = 21  // ipv6 address
};

// stored in one byte
enum SKY_PAYLOAD_TYPE
{
    /* standard payload types */
    PAYLOAD_NONE        = 0, // uninitialized
    LOCATION_RQ         = 1, // location request
    LOCATION_RQ_ADDR    = 2, // location request full

    /* -- errors -- */
    PAYLOAD_ERROR       = 255, // binary protocol errror
    PAYLOAD_API_ERROR   = 254, // api
    SERVER_ERROR        = 253,
    LOCATION_RQ_ERROR   = 252,
    PROBE_REQUEST       = 250,

    DECODE_BIN_FAILED   = 247,
    ENCODE_BIN_FAILED   = 246,
    DECRYPT_BIN_FAILED  = 245,
    ENCRYPT_BIN_FAILED  = 244,
    ENCODE_XML_FAILED   = 243,
    DECODE_XML_FAILED   = 242,
    SOCKET_FAILED       = 241,
    SOCKET_WRITE_FAILED = 240,
    SOCKET_READ_FAILED  = 239,
    SOCKET_TIMEOUT_FAILED = 238,
    CREATE_META_FAILED  = 237,

    /* HTTP response codes */
    /*http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html */
    /* map the http result to 100 - 200 space */
    // HTTP 3xx codes are mapped to 200 -> 100
    HTTP_200            = 100,
    HTTP_201            = 101,
    HTTP_202            = 102,
    HTTP_203            = 103,
    HTTP_204            = 104,
    HTTP_205            = 105,
    HTTP_206            = 106,
    // HTTP 3xx codes are mapped to 300 -> 110
    HTTP_300            = 110,
    HTTP_301            = 121,
    HTTP_302            = 122,
    HTTP_303            = 123,
    HTTP_304            = 124,
    HTTP_305            = 125,
    HTTP_306            = 126,
    HTTP_307            = 127,
    // HTTP 4xx codes are mapped to 400 -> 140
    HTTP_400            = 140,
    HTTP_401            = 141,
    HTTP_402            = 142,
    HTTP_403            = 143,
    HTTP_404            = 144,
    HTTP_405            = 145,
    HTTP_406            = 146,
    HTTP_407            = 147,
    HTTP_408            = 148,
    HTTP_409            = 149,
    HTTP_410            = 150,
    HTTP_411            = 151,
    HTTP_412            = 152,
    HTTP_415            = 155,
    HTTP_416            = 156,
    HTTP_417            = 157,
    // HTTP 5xx codes mapped to 500 -> 180
    HTTP_500            = 180,
    HTTP_501            = 181,
    HTTP_502            = 182,
    HTTP_503            = 183,
    HTTP_504            = 184,
    HTTP_505            = 185,
    // all else
    HTTP_UNKNOWN        = 200

};

/* stores keys in a binary tree */
struct aes_key_t
{
    uint32_t userid;
    unsigned char aes_key[16]; // 128 bit aes key
};

/* WARNING
struct member ordering is important
keep the larger ones first, because
the compiler pads the struct to align
to the largest size */

/* access point struct */
struct ap_t 
{
    unsigned char MAC[6];
    int8_t rssi;
};

// http://wiki.opencellid.org/wiki/API
struct gsm_t
{
    uint32_t ci;
    uint32_t age;
    uint16_t mcc; // country
    uint16_t mnc;
    uint16_t lac;
    int8_t rssi; // -255 unkonwn - map it to - 128
};

struct cdma_t
{
    uint32_t age;
    float lat;
    float lon;
    uint16_t sid;
    uint16_t nid;
    uint16_t bsid;
    int8_t rssi;
};

struct umts_t
{
    uint32_t ci;
    uint32_t age;
    uint16_t mcc; // country
    uint16_t mnc;
    uint16_t lac;
    int8_t rssi;
};

struct lte_t
{
    uint32_t age;
    uint32_t eucid;
    uint16_t mcc;
    uint16_t mnc;
    int8_t rssi;
};

struct gps_t
{
    double lat;
    double lon;
    float alt; // altitude
    float hpe;
    uint32_t age; // last seen in ms
    float speed;
    uint8_t nsat;
    uint8_t fix;
};

struct ble_t
{
    uint16_t major;
    uint16_t minor;
    unsigned char MAC[6];
    unsigned char uuid[16];
    int8_t rssi;
};

/* location result struct */
// define indicates struct size
// this can vary between 32 vs 64 bit systems
#define LOCATION_T_SIZE 20
struct location_t
{
    double lat;
    double lon;
    float hpe;
};

/* extended location data */
struct location_ext_t
{
    float distance_to_point;

    unsigned char ip_type; // DATA_TYPE_IPV4 or DATA_TYPE_IPV6
    unsigned char ipaddr[16]; // used for ipv4 (4 bytes) or ipv6 (16 bytes)

    unsigned char street_num_len;
    char *street_num;

    unsigned char address_len;
    char *address;

    unsigned char city_len;
    char *city;

    unsigned char state_len;
    char *state;

    unsigned char state_code_len;
    char *state_code;

    unsigned char metro1_len;
    char *metro1;

    unsigned char metro2_len;
    char *metro2;

    unsigned char postal_code_len;
    char *postal_code;

    unsigned char county_len;
    char *county;

    unsigned char country_len;
    char *country;

    unsigned char country_code_len;
    char *country_code;
};

struct location_req_t
{
    /* protocol version number */
    unsigned char protocol;

    /* user key */
    struct aes_key_t *key;

    /* client software version */
    unsigned char version;

    /* client device MAC identifier */
    unsigned char MAC[6];

    /* payload type */
    unsigned char payload_type;

    /* wifi access points */
    unsigned char ap_count;
    struct ap_t *aps;

    /* ble beacons */
    unsigned char ble_count;
    struct ble_t *bles;

    /* cell */
    // cell count refers to one of the struct count below
    unsigned char cell_count;
    unsigned char cell_type; // SKY_DATA_TYPE

    struct gsm_t *gsm;
    struct cdma_t *cdma;
    struct lte_t *lte;
    struct umts_t *umts;

    /* gps */
    unsigned char gps_count;
    struct gps_t *gps;

    /* http server settings */
    char *http_url;
    char *http_uri;

    /* api server version number (string 2.34) */
    char *api_version;
};

struct location_resp_t
{
    /* timestamp */
    uint64_t timestamp; // in ms

    /* protocol version number */
    unsigned char protocol;

    /* server software version */
    unsigned char version;

    /* user key */
    struct aes_key_t *key;

    /* payload type */
    unsigned char payload_type;

    /* location result */
    struct location_t location;

    /* ext location res, adress etc */
    struct location_ext_t location_ex;
};

#endif

#ifdef __cplusplus
}
#endif
