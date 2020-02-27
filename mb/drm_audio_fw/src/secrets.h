#pragma once
#ifndef SECRETS_H
#define SECRETS_H

#include "constants.h"

#define TOTAL_USERS 64
#define TOTAL_REGIONS 32

struct user {
    const char name[UNAME_SIZE]; //the username. this is used to check song owners/shared withs.
    const uint8_t salt[SALT_SIZE]; //the salt to pass to the hash function.
    const uint8_t kpublic[PKEY_SIZE]; //the user's public key.
}; //these should be set as const in the secrets header file.

static const uint8_t mipod_pubkey[EDDSA_PUBLIC_SIZE]; //public signing key for the firmware
static struct user provisioned_users[TOTAL_USERS]; //the users that can use the device
static uint32_t provisioned_regions[TOTAL_REGIONS] = { INVALID_RID }; //for now, initialize them all to be invalid. (may require 32x INVALID_RID)

#endif // !SECRETS_H