#pragma once
#ifndef CONSTANTS_H
#define CONSTANTS_H

#include "xil_printf.h"

//from constants.h mitre file:
#define MAX_SONG_SZ (1<<25) //33554432 == 32 mib (more than system ram lol)

#define PKEY_SIZE 64 //see: hmac keygen
#define UNAME_SIZE 16 //see: ectf requirements (it is actually 15, but each name is nul-padded to 16 for obvious reasons)
#define SALT_SIZE 16 //see: common sense
#define PIN_SIZE 64 //see: ectf requirement

#define HASH_SIZE 64

#define INVALID_UID -1
#define MAX_SHARED_USERS 64 //see: ectf requirements, 3.3.5

#define EDDSA_SECRET_SIZE 32 //I think it may actually be 64, but it looks like 1/2 of that is the "random" number generated and 1/2 the public key, so who knows?
#define EDDSA_PUBLIC_SIZE 32
#define SODIUM_EDDSA_SECRET_SIZE (EDDSA_SECRET_SIZE + EDDSA_PUBLIC_SIZE)
#define EDDSA_SIG_SIZE 64 

#define ARGON2_THREADS 1
#define ARGON2_LANES 1
#define INVALID_UID -1
#define MAX_SHARED_USERS 64 //see: ectf requirements, 3.3.5

#define HMAC_SIG_SIZE 64

#define CIPHER_BLOCKSIZE 64 //the block size of the stream cipher being used for song encryption.
//useage of chacha20 or aes-256 is recommended.
#define KEY_IOPAD_SIZE128 128

#define MAX_SHARED_REGIONS 32
#define REGION_NAME_SZ 64
#define MAX_QUERY_REGIONS MAX_SHARED_REGIONS /*TOTAL_REGIONS*/
#define INVALID_RID -1

#define SHARED_DDR_BASE (0x20000000 + 0x1CC00000) //from mitre constants.h, this may need to change

#define SEGMENT_BUF_SIZE 32000 //14336+128 KB, pretty pricey but w/e for now
#define CHUNK_SZ 16000
#define SEGMENT_SONG_SIZE (SEGMENT_BUF_SIZE - sizeof(struct segment_trailer))

#define PCM_DRV_BUFFER_SIZE 16000  // 0x3e80
#define FIFO_CAP 4096*4

// printing utility
#define MB_PROMPT "\r\nMB> "
#define mb_printf(...) xil_printf(MB_PROMPT __VA_ARGS__)
#define MB_PROMPT_DEBUG "\r\nMB_DEBUG> "
#define mb_debug(...) xil_printf(MB_PROMPT_DEBUG __VA_ARGS__)

// LED colors and controller
struct color {
    u32 r;
    u32 g;
    u32 b;
};

// simulate array of 64B names without pointer indirection
#define q_region_lookup(q, i) (q.regions + (i * REGION_NAME_SZ))
#define q_song_region_lookup(q,i) (q.song_regions + (i * REGION_NAME_SZ))
#define q_user_lookup(q, i) (q.users_list + (i * UNAME_SIZE))

// query information for song (drm)
// #define q_song_region_lookup(q, i) (q.regions[i])
#define q_song_user_lookup(q, i) (q.shared_users[UNAME_SIZE][i])

#endif // !CONSTANTS_H
