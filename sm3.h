
#ifndef HEADER_SM3_H
#define HEADER_SM3_H

#define SM3_DIGEST_SIZE		32
#define SM3_BLOCK_SIZE		64
#define SM3_CBLOCK		(SM3_BLOCK_SIZE)
#define SM3_HMAC_SIZE		(SM3_DIGEST_SIZE)


#include <stdint.h>
#include <unistd.h>

struct sm3_ctx {
	uint32_t digest[8];
	uint64_t nblocks;
	unsigned char block[64];
	int num;
};


int sm3_init(struct sm3_ctx *ctx);
int sm3_update(struct sm3_ctx *ctx, const unsigned char *data, 
			 size_t data_len);
int sm3_final(struct sm3_ctx *ctx, unsigned char *digest, size_t dlen);
#endif
