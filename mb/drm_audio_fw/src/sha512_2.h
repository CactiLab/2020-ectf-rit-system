#ifndef SHA512_H
#define SHA512_H

#include <stddef.h>
#include <stdint.h>

#define SHA512_BLOCK_SIZE	128
#define SHA512_HASH_LENGTH	64


typedef struct {
	uint64_t	state[8];
	uint64_t	count;

	uint8_t		buffer[SHA512_BLOCK_SIZE];
	unsigned long	fill;
} sha512ctx;



void sha512_init_2(sha512ctx *ctx);
void sha512_update_2(sha512ctx *ctx, const void *data, size_t len);
void sha512_done_2(sha512ctx *ctx, uint8_t out[SHA512_HASH_LENGTH]);



#endif
