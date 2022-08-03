#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include "sm3.h" 

static int
print_out(int bsdstyle, FILE * fout, const char *fname,
		 unsigned char *hash, size_t hashlen)
{
	size_t i = 0;

	if (!fout || !hash || hashlen != SM3_DIGEST_SIZE)
		return -1;

	if (bsdstyle)
		fprintf(fout, "%s (%s) = ", "sm3", fname);

	for (i = 0; i < hashlen; i++)
		fprintf(fout, "%02x", hash[i]);

	if (bsdstyle)
		fprintf(fout, "\n");
	else
		fprintf(fout, "  %s\n", fname);

	return 0;
}

int main(int argc, char **argv)
{
	struct sm3_ctx ctx; 
	unsigned char digest[SM3_DIGEST_SIZE] = {0};

	long bs = 4096;
	int count = 1024;
	int i = 0;
	unsigned char *buf = NULL;

	struct timeval tv1, tv2;
	long t_time = 1024;

	int ret = -1;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s blocksize count\n", argv[0]);
		return -1;
	}

	bs = strtol(argv[1], NULL, 10);
	count = strtol(argv[2], NULL, 10);

	buf = calloc(bs, 1);
	if (!buf)
		goto end;
	
	gettimeofday(&tv1, NULL);

	sm3_init(&ctx);
	i = count; 
	while (i--) {
		sm3_update(&ctx, buf, bs);
	}
	sm3_final(&ctx, digest, sizeof(digest));
	gettimeofday(&tv2, NULL);
	print_out(1, stdout, "zerobuf", digest, sizeof(digest));

	t_time = tv2.tv_usec + tv2.tv_sec*1000*1000 - tv1.tv_usec - tv1.tv_sec*1000*1000;
        fprintf(stdout, "Total hashed size:%ld bytes, cost:%lu ms. Avg:%lf M/s\n", bs*count, t_time, 
			bs*count/1024/1024/(t_time/1000000.0));

	ret = 0;

end:
	if (buf)
		free(buf);
	return ret;
}
