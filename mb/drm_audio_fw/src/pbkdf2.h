#pragma once
#ifndef PBKDF2_H
#define PBKDF2_H


#include <stddef.h>
#include <stdint.h>
#include "crypto_hash_sha512.h"

//below uses SHA2-512 from libsodium. would like to use SHA3-512 at some point but oh well
#define hash_state_t crypto_hash_sha512_state
#define HASH_INIT(p_state) crypto_hash_sha512_init(p_state)
#define HASH_UPDATE(p_state,buf,buflen) crypto_hash_sha512_update((p_state),(buf),(buflen))
#define HASH_FINAL(p_state,outbuf)  crypto_hash_sha512_final((p_state),(outbuf))
#define HASH_BLKSIZE crypto_hash_sha512_BYTES
#define HASH_OUTSIZE crypto_hash_sha512_BYTES
#define KEY_IOPAD_SIZE 64
#define KEY_IOPAD_SIZE128 128
#define   SHA1_DIGEST_SIZE  20
#define SHA512_DIGEST_SIZE  64

#define KDF_OUTSIZE HASH_OUTSIZE //the desired output size of the derived key. equal to hash output size.
#define KDF_ITER 4096 //this needs to go up alot lol
#define KDF_SALTSIZE 16 //gets padded, all good

/*
performs the pbkdf2 function on the pasword <pw> with length <pwlen>, using a salt <salt>.
writes the derived key into <out>
*/
void pbkdf2(const uint8_t* pw, size_t pwlen, const uint8_t salt[KDF_SALTSIZE], uint8_t out[KDF_OUTSIZE]);

/*
computes a sha2-512 hmac of <msg> using <key> into <out>
*/
void hmac(uint8_t key[HASH_BLKSIZE], const uint8_t* msg, size_t msgsize, uint8_t out[SHA512_DIGEST_SIZE]);
void hmac_sha1(uint8_t key[HASH_BLKSIZE], const uint8_t* msg, size_t msgsize, uint8_t out[SHA1_DIGEST_SIZE]);

#endif // !PBKDF2_H
