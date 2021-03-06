#ifndef __sso_packet_h
#define __sso_packet_h

#include <sodium.h>

#include "tai.h"
#include "types.h"
#include "ticket.h"

struct sso_packet
{
    enum PACKET_TYPE
    {
        PING,
        PONG,
        STAGE1_CLIENT_TO_SERVER,
        STAGE1_SERVER_TO_CLIENT,
        STAGE2_CLIENT_TO_SERVER,
        STAGE2_SERVER_TO_CLIENT
    } type;
    char publickey[crypto_box_PUBLICKEYBYTES];
    char nonce[crypto_box_NONCEBYTES];
    char mac[crypto_box_MACBYTES];

    int length;
    struct sso_packet_payload
    {
        struct sso_ticket ticket;
        char ticketmac[crypto_box_MACBYTES];

        struct taia currenttime;

        union
        {
            struct sso_packet_s1_c2s
            {
                unsigned char username[USERNAME_LENGTH];
                unsigned char password[PASSWORD_LENGTH];
                unsigned char hostname[HOSTNAME_LENGTH];
            } s1_c2s;

            struct sso_packet_s1_s2c
            {

            } s1_s2c;

            struct sso_packet_s2_c2s
            {
                unsigned char target[TARGET_LENGTH];
            } s2_c2s;

            struct sso_packet_s2_s2c
            {

            } s2_s2c;
        };
    } payload;

    char padding[crypto_box_SEALBYTES];
};

#endif
