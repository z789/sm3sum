#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sm3.h"

#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))
#define cpu_to_be32(n) ((((n)&0x000000ff)<<24) | (((n)&0x0000ff00)<<8) \
			| (((n)&0x00ff0000)>>8) | (((n)&0xff000000)>>24))

#define cpu_to_be64(n) ((((n)&0x00000000000000ff)<<56) | (((n)&0x000000000000ff00)<<40) \
			| (((n)&0x0000000000ff0000)<<24) | (((n)&0x00000000ff000000)<<8)\
			| (((n)&0x000000ff00000000)>>8) | (((n)&0x0000ff0000000000)>>24)\
			| (((n)&0x00ff000000000000)>>40) | (((n)&0xff00000000000000)>>56))               

static void sm3_compress(uint32_t digest[8], const unsigned char block[64]);

int sm3_init(struct sm3_ctx *ctx)
{
	if (!ctx)
		return -1;

	ctx->digest[0] = 0x7380166F;
	ctx->digest[1] = 0x4914B2B9;
	ctx->digest[2] = 0x172442D7;
	ctx->digest[3] = 0xDA8A0600;
	ctx->digest[4] = 0xA96F30BC;
	ctx->digest[5] = 0x163138AA;
	ctx->digest[6] = 0xE38DEE4D;
	ctx->digest[7] = 0xB0FB0E4E;

	ctx->nblocks = 0;
	ctx->num = 0;

	return 0;
}

int sm3_update(struct sm3_ctx *ctx, const unsigned char *data,
			 size_t data_len)
{
	if (!ctx || !data || data_len < 0)
		return -1;

	if (ctx->num) {
		unsigned int left = SM3_BLOCK_SIZE - ctx->num;

		if (data_len < left) {
			memcpy(ctx->block + ctx->num, data, data_len);
			ctx->num += data_len;
			return 0;
		} else {
			memcpy(ctx->block + ctx->num, data, left);
			sm3_compress(ctx->digest, ctx->block);
			ctx->nblocks++;
			data += left;
			data_len -= left;
		}
	}

	while (data_len >= SM3_BLOCK_SIZE) {
		sm3_compress(ctx->digest, data);
		ctx->nblocks++;
		data += SM3_BLOCK_SIZE;
		data_len -= SM3_BLOCK_SIZE;
	}
	ctx->num = data_len;
	if (data_len)
		memcpy(ctx->block, data, data_len);

	return 0;
}

int sm3_final(struct sm3_ctx *ctx, unsigned char *digest, size_t dlen)
{
	int i;
	uint32_t *pdigest;
	uint64_t *count;

	if (!ctx || !digest || dlen < SM3_DIGEST_SIZE)
		return -1;

	pdigest = (uint32_t *)digest;
	count = (uint64_t *)(ctx->block + SM3_BLOCK_SIZE - 8);

	ctx->block[ctx->num] = 0x80;

	if (ctx->num + 9 <= SM3_BLOCK_SIZE) {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 9);
	} else {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 1);
		sm3_compress(ctx->digest, ctx->block);
		memset(ctx->block, 0, SM3_BLOCK_SIZE - 8);
	}

	count[0] = cpu_to_be64((ctx->nblocks << 9) + (ctx->num << 3));

	sm3_compress(ctx->digest, ctx->block);
	for (i = 0; i < ARRAY_SIZE(ctx->digest); i++)
		pdigest[i] = cpu_to_be32(ctx->digest[i]);

	return 0;
}

#define ROTATELEFT(X, n)  (((X)<<(n)) | ((X)>>(32-(n))))
#define ROTATELEFT64(X, n)  (((X)<<((n)-32)) | ((X)>>(64-(n))))

#define P0(x) ((x) ^  ROTATELEFT((x), 9)  ^ ROTATELEFT((x), 17))
#define P1(x) ((x) ^  ROTATELEFT((x), 15) ^ ROTATELEFT((x), 23))

#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))

#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))


static const uint32_t T16 = 0x79CC4519;
static const uint32_t T64 = 0x7A879D8A;

#ifdef SM3_MACRO
#define W16_INIT(WP, pb)                     \
	do {                                 \
		WP[0] = cpu_to_be32(pb[0]);  \
		WP[1] = cpu_to_be32(pb[1]);  \
		WP[2] = cpu_to_be32(pb[2]);  \
		WP[3] = cpu_to_be32(pb[3]);  \
		WP[4] = cpu_to_be32(pb[4]);  \
		WP[5] = cpu_to_be32(pb[5]);  \
		WP[6] = cpu_to_be32(pb[6]);  \
		WP[7] = cpu_to_be32(pb[7]);  \
		WP[8] = cpu_to_be32(pb[8]);  \
		WP[9] = cpu_to_be32(pb[9]);  \
		WP[10] = cpu_to_be32(pb[10]);  \
		WP[11] = cpu_to_be32(pb[11]);  \
		WP[12] = cpu_to_be32(pb[12]);  \
		WP[13] = cpu_to_be32(pb[13]);  \
		WP[14] = cpu_to_be32(pb[14]);  \
		WP[15] = cpu_to_be32(pb[15]);  \
	} while (0)

#define W68_UNIT(WP, jp)                                              \
	(WP[jp] = P1(WP[jp-16] ^ WP[jp-9] ^ ROTATELEFT(WP[jp-3], 15)) \
		 ^ ROTATELEFT(WP[jp - 13], 7) ^ WP[jp-6])

#define W68_INIT(WP)                               \
	do {                                       \
		W68_UNIT(WP, 16);                  \
		W68_UNIT(WP, 17);                  \
		W68_UNIT(WP, 18);                  \
		W68_UNIT(WP, 19);                  \
		W68_UNIT(WP, 20);                  \
		W68_UNIT(WP, 21);                  \
		W68_UNIT(WP, 22);                  \
		W68_UNIT(WP, 23);                  \
		W68_UNIT(WP, 24);                  \
		W68_UNIT(WP, 25);                  \
		W68_UNIT(WP, 26);                  \
		W68_UNIT(WP, 27);                  \
		W68_UNIT(WP, 28);                  \
		W68_UNIT(WP, 29);                  \
		W68_UNIT(WP, 30);                  \
		W68_UNIT(WP, 31);                  \
		W68_UNIT(WP, 32);                  \
		W68_UNIT(WP, 33);                  \
		W68_UNIT(WP, 34);                  \
		W68_UNIT(WP, 35);                  \
		W68_UNIT(WP, 36);                  \
		W68_UNIT(WP, 37);                  \
		W68_UNIT(WP, 38);                  \
		W68_UNIT(WP, 39);                  \
		W68_UNIT(WP, 40);                  \
		W68_UNIT(WP, 41);                  \
		W68_UNIT(WP, 42);                  \
		W68_UNIT(WP, 43);                  \
		W68_UNIT(WP, 44);                  \
		W68_UNIT(WP, 45);                  \
		W68_UNIT(WP, 46);                  \
		W68_UNIT(WP, 47);                  \
		W68_UNIT(WP, 48);                  \
		W68_UNIT(WP, 49);                  \
		W68_UNIT(WP, 50);                  \
		W68_UNIT(WP, 51);                  \
		W68_UNIT(WP, 52);                  \
		W68_UNIT(WP, 53);                  \
		W68_UNIT(WP, 54);                  \
		W68_UNIT(WP, 55);                  \
		W68_UNIT(WP, 56);                  \
		W68_UNIT(WP, 57);                  \
		W68_UNIT(WP, 58);                  \
		W68_UNIT(WP, 59);                  \
		W68_UNIT(WP, 60);                  \
		W68_UNIT(WP, 61);                  \
		W68_UNIT(WP, 62);                  \
		W68_UNIT(WP, 63);                  \
		W68_UNIT(WP, 64);                  \
		W68_UNIT(WP, 65);                  \
		W68_UNIT(WP, 66);                  \
		W68_UNIT(WP, 67);                  \
	} while (0)
	
#define FOR16_UNIT(jp)                                                             \
	do {                                                                       \
		SS1 = ROTATELEFT((ROTATELEFT(A, 12) + E + ROTATELEFT(T16, jp)), 7);\
		SS2 = SS1 ^ ROTATELEFT(A, 12);                                     \
		TT1 = FF0(A, B, C) + D + SS2 + (W[jp] ^ W[jp+4]);                  \
		TT2 = GG0(E, F, G) + H + SS1 + W[jp];                              \
		D = C;                                                             \
		C = ROTATELEFT(B, 9);                                              \
		B = A;                                                             \
		A = TT1;                                                           \
		H = G;                                                             \
		G = ROTATELEFT(F, 19);                                             \
		F = E;                                                             \
		E = P0(TT2);                                                       \
	} while (0)                                                                
                                                                                   
#define FOR64_UNIT(jp)                                                             \
	do {                                                                       \
		SS1 = ROTATELEFT((ROTATELEFT(A, 12) + E + ROTATELEFT(T64, jp)), 7);\
		SS2 = SS1 ^ ROTATELEFT(A, 12);                                     \
		TT1 = FF1(A, B, C) + D + SS2 + (W[jp] ^ W[jp+4]);                  \
		TT2 = GG1(E, F, G) + H + SS1 + W[jp];                              \
		D = C;                                                             \
		C = ROTATELEFT(B, 9);                                              \
		B = A;                                                             \
		A = TT1;                                                           \
		H = G;                                                             \
		G = ROTATELEFT(F, 19);                                             \
		F = E;                                                             \
		E = P0(TT2);                                                       \
	} while (0)                                                                

#define FOR64_UNIT64(jp)                                                           \
	do {                                                                       \
		SS1 = ROTATELEFT((ROTATELEFT(A, 12) + E + ROTATELEFT64(T64, jp)), 7);\
		SS2 = SS1 ^ ROTATELEFT(A, 12);                                     \
		TT1 = FF1(A, B, C) + D + SS2 + (W[jp] ^ W[jp+4]);                  \
		TT2 = GG1(E, F, G) + H + SS1 + W[jp];                              \
		D = C;                                                             \
		C = ROTATELEFT(B, 9);                                              \
		B = A;                                                             \
		A = TT1;                                                           \
		H = G;                                                             \
		G = ROTATELEFT(F, 19);                                             \
		F = E;                                                             \
		E = P0(TT2);                                                       \
	} while (0)                                                                

#define FOR16                  \
	do {                   \
		FOR16_UNIT(0); \
		FOR16_UNIT(1); \
		FOR16_UNIT(2); \
		FOR16_UNIT(3); \
		FOR16_UNIT(4); \
		FOR16_UNIT(5); \
		FOR16_UNIT(6); \
		FOR16_UNIT(7); \
		FOR16_UNIT(8); \
		FOR16_UNIT(9); \
		FOR16_UNIT(10); \
		FOR16_UNIT(11); \
		FOR16_UNIT(12); \
		FOR16_UNIT(13); \
		FOR16_UNIT(14); \
		FOR16_UNIT(15); \
	} while (0)

#define FOR64                   \
	do {                    \
		FOR64_UNIT(16); \
		FOR64_UNIT(17); \
		FOR64_UNIT(18); \
		FOR64_UNIT(19); \
		FOR64_UNIT(20); \
		FOR64_UNIT(21); \
		FOR64_UNIT(22); \
		FOR64_UNIT(23); \
		FOR64_UNIT(24); \
		FOR64_UNIT(25); \
		FOR64_UNIT(26); \
		FOR64_UNIT(27); \
		FOR64_UNIT(28); \
		FOR64_UNIT(29); \
		FOR64_UNIT(30); \
		FOR64_UNIT(31); \
		FOR64_UNIT(32); \
		FOR64_UNIT64(33); \
		FOR64_UNIT64(34); \
		FOR64_UNIT64(35); \
		FOR64_UNIT64(36); \
		FOR64_UNIT64(37); \
		FOR64_UNIT64(38); \
		FOR64_UNIT64(39); \
		FOR64_UNIT64(40); \
		FOR64_UNIT64(41); \
		FOR64_UNIT64(42); \
		FOR64_UNIT64(43); \
		FOR64_UNIT64(44); \
		FOR64_UNIT64(45); \
		FOR64_UNIT64(46); \
		FOR64_UNIT64(47); \
		FOR64_UNIT64(48); \
		FOR64_UNIT64(49); \
		FOR64_UNIT64(50); \
		FOR64_UNIT64(51); \
		FOR64_UNIT64(52); \
		FOR64_UNIT64(53); \
		FOR64_UNIT64(54); \
		FOR64_UNIT64(55); \
		FOR64_UNIT64(56); \
		FOR64_UNIT64(57); \
		FOR64_UNIT64(58); \
		FOR64_UNIT64(59); \
		FOR64_UNIT64(60); \
		FOR64_UNIT64(61); \
		FOR64_UNIT64(62); \
		FOR64_UNIT64(63); \
	} while (0)

static void sm3_compress(uint32_t digest[8], const unsigned char block[64])             
{
	uint32_t W[68];
	const uint32_t *pblock = (const uint32_t *)block;

	uint32_t A = digest[0];
	uint32_t B = digest[1];
	uint32_t C = digest[2];
	uint32_t D = digest[3];
	uint32_t E = digest[4];
	uint32_t F = digest[5];
	uint32_t G = digest[6];
	uint32_t H = digest[7];
	uint32_t SS1, SS2, TT1, TT2;

	W16_INIT(W, pblock);
	W68_INIT(W);

	FOR16;
	FOR64;

	digest[0] ^= A;
	digest[1] ^= B;
	digest[2] ^= C;
	digest[3] ^= D;
	digest[4] ^= E;
	digest[5] ^= F;
	digest[6] ^= G;
	digest[7] ^= H;
}
#else //SM3_MACRO
static void sm3_compress(uint32_t digest[8], const unsigned char block[64])
{
	int j;
	uint32_t W[68];
	const uint32_t *pblock = (const uint32_t *)block;

	uint32_t A = digest[0];
	uint32_t B = digest[1];
	uint32_t C = digest[2];
	uint32_t D = digest[3];
	uint32_t E = digest[4];
	uint32_t F = digest[5];
	uint32_t G = digest[6];
	uint32_t H = digest[7];
	uint32_t SS1, SS2, TT1, TT2;

	for (j = 0; j < 16; j++)
		W[j] = cpu_to_be32(pblock[j]);
	for (j = 16; j < 68; j++)
		W[j] = P1(W[j-16] ^ W[j-9] ^ ROTATELEFT(W[j-3], 15)) ^ ROTATELEFT(W[j - 13], 7) ^ W[j-6];

	for (j = 0; j < 16; j++) {

		SS1 = ROTATELEFT((ROTATELEFT(A, 12) + E + ROTATELEFT(T16, j)), 7);
		SS2 = SS1 ^ ROTATELEFT(A, 12);
		TT1 = FF0(A, B, C) + D + SS2 + (W[j] ^ W[j+4]);
		TT2 = GG0(E, F, G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F, 19);
		F = E;
		E = P0(TT2);
	}

	for (j = 16; j < 64; j++) {

		SS1 = ROTATELEFT((ROTATELEFT(A, 12) + E + ROTATELEFT(T64, j)), 7);
		SS2 = SS1 ^ ROTATELEFT(A, 12);
		TT1 = FF1(A, B, C) + D + SS2 + (W[j] ^ W[j+4]);
		TT2 = GG1(E, F, G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F, 19);
		F = E;
		E = P0(TT2);
	}

	digest[0] ^= A;
	digest[1] ^= B;
	digest[2] ^= C;
	digest[3] ^= D;
	digest[4] ^= E;
	digest[5] ^= F;
	digest[6] ^= G;
	digest[7] ^= H;
}
#endif

