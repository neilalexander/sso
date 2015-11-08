#ifndef __sso_types_h
#define __sso_types_h

#include <sodium.h>

#include "types.h"

struct sso_ticket
{
    uint8_t publickey[crypto_box_PUBLICKEYBYTES];
    char target[TARGET_LENGTH];
    char username[USERNAME_LENGTH];
    char hostname[HOSTNAME_LENGTH];

    struct taia expiry;
};

struct sso_request
{
    uint8_t publickey[crypto_box_PUBLICKEYBYTES];
    char username[USERNAME_LENGTH];
};

#endif
