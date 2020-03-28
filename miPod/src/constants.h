#pragma once
#ifndef CONSTANTS_H
#define CONSTANTS_H

//from constants.h mitre file:
#define MAX_SONG_SZ (1<<25) //33554432 == 32 mib (more than system ram lol)

#define REGION_NAME_SZ 64
#define PKEY_SIZE 64 //see: hmac keygen
#define UNAME_SIZE 16 //see: ectf requirements (it is actually 15, but each name is nul-padded to 16 for obvious reasons)
#define SALT_SIZE 16 //see: common sense
#define PIN_SIZE 64 //see: ectf requirements

#define ARGON2_THREADS 1
#define ARGON2_LANES 1
#define INVALID_UID -1
#define MAX_SHARED_USERS 64 //see: ectf requirements, 3.3.5

#define HMAC_SIG_SIZE 64

#define CIPHER_BLOCKSIZE 64 //the block size of the stream cipher being used for song encryption.
//useage of chacha20 or aes-256 is recommended.

#define MAX_SHARED_REGIONS 32
#define REGION_NAME_SZ 64
#define MAX_QUERY_REGIONS MAX_SHARED_REGIONS /*TOTAL_REGIONS*/
#define INVALID_RID -1

#define SHARED_DDR_BASE (0x20000000 + 0x1CC00000) //from mitre constants.h, this may need to change

#define SEGMENT_BUF_SIZE 32000 //14400+128 KB
#define SEGMENT_SONG_SIZE (SEGMENT_BUF_SIZE - sizeof(struct segment_trailer))

#endif // !CONSTANTS_H
