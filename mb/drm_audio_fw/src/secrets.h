//#pragma once
//#ifndef SECRETS_H
//#define SECRETS_H
//
//#include "constants.h"
//
//#define TOTAL_USERS 64
//#define TOTAL_REGIONS 32
//
//struct user {
//    const char name[UNAME_SIZE]; //the username. this is used to check song owners/shared withs.
//    const uint8_t salt[SALT_SIZE]; //the salt to pass to the hash function.
//    uint8_t hash[HASH_SIZE]; //the user's public key.
//}; //these should be set as const in the secrets header file.
//
//static uint8_t mipod_key[HASH_SIZE]; //firmware hmac key. can't be const because it gets written to.
//static const uint8_t mipod_salt[SALT_SIZE]; //firmware salt
//static struct user provisioned_users[TOTAL_USERS]; //the users that can use the device
//static uint32_t provisioned_regions[TOTAL_REGIONS] = { INVALID_RID }; //for now, initialize them all to be invalid. (may require 32x INVALID_RID)
//
//#endif // !SECRETS_H



#pragma once
#ifndef SECRETS_H
#define SECRETS_H
#include "constants.h"

#define TOTAL_USERS 3
#define TOTAL_REGIONS 2


struct user {
    const char name[UNAME_SIZE];
    const uint8_t salt[SALT_SIZE];
    const uint8_t hash[PKEY_SIZE];
};

static const uint8_t mipod_key[PKEY_SIZE] = {36, 183, 176, 197, 162, 2, 78, 142, 158, 92, 81, 103, 3, 172, 217, 135, 229, 254, 156, 170, 121, 213, 164, 139, 141, 236, 94, 70, 146, 122, 82, 47, 167, 188, 240, 85, 215, 240, 27, 67, 155, 74, 224, 144, 165, 239, 47, 142, 193, 94, 205, 171, 85, 186, 243, 23, 146, 58, 35, 68, 40, 238, 150, 72 }; //public signing key for the firmware size 64
static const uint8_t mipod_salt[SALT_SIZE] ={242, 211, 32, 82, 174, 224, 245, 81, 248, 33, 13, 6, 54, 141, 44, 219 }; //public slat  for the firmware size 16
static struct user provisioned_users[TOTAL_USERS] = { {"drew",{120, 33, 100, 115, 186, 210, 143, 29, 162, 173, 149, 3, 72, 91, 145, 189},{50, 46, 218, 206, 131, 28, 219, 121, 121, 63, 46, 12, 184, 188, 11, 27, 80, 205, 94, 143, 41, 135, 218, 52, 48, 229, 248, 67, 225, 4, 2, 241, 215, 241, 104, 144, 129, 105, 237, 85, 4, 15, 93, 114, 121, 247, 17, 247, 180, 153, 204, 154, 143, 247, 224, 204, 121, 35, 140, 52, 252, 142, 54, 68}}, {"ben",{10, 211, 28, 132, 91, 196, 181, 79, 24, 42, 34, 215, 23, 164, 238, 53},{57, 28, 236, 254, 16, 58, 233, 85, 179, 66, 3, 226, 250, 136, 90, 201, 235, 41, 219, 37, 5, 84, 40, 57, 212, 225, 208, 151, 10, 198, 110, 127, 233, 121, 220, 222, 174, 107, 207, 30, 189, 160, 10, 75, 166, 161, 158, 49, 184, 207, 78, 87, 24, 235, 114, 129, 165, 136, 73, 24, 83, 104, 197, 103}}, {"misha",{11, 146, 150, 42, 161, 21, 168, 77, 0, 180, 133, 105, 243, 43, 132, 2},{206, 203, 11, 235, 15, 24, 186, 153, 174, 23, 35, 148, 59, 19, 20, 18, 62, 206, 155, 3, 22, 29, 202, 27, 50, 237, 147, 96, 249, 107, 83, 87, 40, 41, 14, 177, 94, 45, 197, 41, 132, 113, 74, 192, 49, 175, 136, 93, 82, 135, 100, 226, 186, 170, 143, 24, 29, 177, 79, 72, 66, 16, 72, 76}} };

const uint32_t provisioned_regions[TOTAL_REGIONS] = { 0, 1 };
const char *REGION_NAMES[] = { "United States", "Japan"};


#endif // SECRETS_H
