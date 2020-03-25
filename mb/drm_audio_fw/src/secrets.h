
#pragma once
#ifndef SECRETS_H
#define SECRETS_H
#include "constants.h"
#define TOTAL_USERS 3
#define TOTAL_REGIONS 2
#define NUM_REGIONS 3
struct user {
    const char name[UNAME_SIZE]; 
    const uint8_t salt[SALT_SIZE]; 
    const uint8_t hash[PKEY_SIZE]; 
}; 
static const uint8_t mipod_key[PKEY_SIZE] = {131, 218, 164, 154, 141, 13, 172, 255, 38, 91, 244, 41, 213, 73, 63, 69, 143, 104, 247, 51, 4, 0, 11, 5, 137, 3, 57, 214, 243, 118, 184, 87, 130, 43, 158, 247, 54, 54, 175, 91, 64, 60, 199, 148, 111, 12, 103, 103, 188, 40, 195, 200, 154, 42, 143, 202, 252, 26, 56, 64, 55, 87, 34, 79 }; //public signing key for the firmware size 64
static const uint8_t mipod_salt[SALT_SIZE] ={52, 25, 18, 158, 4, 54, 189, 250, 77, 199, 13, 39, 112, 61, 245, 132 }; //public slat  for the firmware size 16
static struct user provisioned_users[TOTAL_USERS] = { {"drew",{25, 172, 202, 116, 234, 83, 199, 36, 80, 130, 71, 173, 145, 138, 63, 130},{35, 96, 202, 218, 166, 30, 62, 26, 62, 173, 28, 58, 172, 104, 197, 182, 227, 150, 49, 252, 150, 195, 81, 228, 81, 92, 160, 222, 219, 228, 196, 164, 185, 49, 20, 61, 178, 127, 48, 118, 215, 171, 123, 60, 182, 246, 238, 126, 159, 116, 212, 243, 105, 240, 170, 225, 56, 84, 97, 94, 17, 21, 150, 229}}, {"ben",{59, 151, 231, 161, 216, 148, 224, 103, 201, 246, 196, 107, 125, 69, 67, 211},{154, 179, 167, 171, 182, 18, 114, 179, 48, 182, 178, 15, 23, 247, 215, 181, 22, 227, 175, 133, 26, 25, 127, 51, 116, 108, 163, 199, 197, 49, 210, 123, 169, 51, 196, 55, 164, 21, 134, 100, 186, 18, 135, 230, 161, 121, 207, 233, 147, 198, 127, 31, 85, 64, 132, 83, 131, 76, 120, 20, 104, 184, 235, 168}}, {"misha",{216, 58, 54, 192, 78, 18, 101, 94, 30, 133, 28, 172, 221, 249, 249, 42},{21, 86, 123, 166, 37, 52, 253, 90, 9, 198, 225, 113, 199, 31, 184, 69, 186, 180, 72, 166, 127, 243, 79, 10, 226, 202, 217, 255, 83, 231, 200, 117, 133, 26, 54, 236, 227, 4, 17, 83, 228, 164, 108, 143, 155, 188, 190, 110, 151, 1, 216, 82, 130, 124, 233, 17, 83, 18, 16, 225, 156, 45, 215, 0}} };
static uint32_t provisioned_regions[TOTAL_REGIONS] = { 0, 1 };
const uint32_t REGION_IDS[] = { 0, 1, 2 };
const char *REGION_NAMES[] = { "United States", "Japan", "Australia" };
#endif // SECRETS_H