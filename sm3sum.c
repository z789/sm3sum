#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include "sm3.h"

#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))

static const char *sm3name = "SM3";

static int sm3_stream(FILE *stream, void *out, size_t outlen)
{
	int ret = -1;
	size_t n;
	struct sm3_ctx ctx;
	const size_t buf_len = 65536;
	uint8_t *buf = (uint8_t *) malloc(buf_len);

	if (!stream || !out || !buf || outlen != SM3_DIGEST_SIZE)
		goto end;

	sm3_init(&ctx);

	while (!feof(stream)) {
		n = fread(buf, 1, buf_len, stream);

		if (ferror(stream))
			goto end;

		if (n > 0)
			sm3_update(&ctx, buf, n);
	}

	sm3_final(&ctx, out, outlen);
	ret = 0;

 end:
	free(buf);
	return ret;
}

static int sm3_file(const char *fname, void *out, size_t outlen)
{
	FILE *f = NULL;
	int ret = -1;

	if (!fname || !out || outlen != SM3_DIGEST_SIZE)
		return -1;

	if (fname[0] == '-' && fname[1] == '\0')
		f = stdin;
	else
		f = fopen(fname, "rb");

	if (!f) {
		fprintf(stderr, "Could not open `%s': %s\n", fname,
			strerror(errno));
		return ret;
	}

	if (sm3_stream(f, out, outlen) < 0)
		fprintf(stderr, "Failed to hash `%s'\n", fname);
	else
		ret = 0;

	if (f != stdin)
		fclose(f);

	return ret;
}

static int
print_out(int bsdstyle, FILE * fout, const char *fname,
		 unsigned char *hash, size_t hashlen)
{
	size_t i = 0;

	if (!fout || !hash || hashlen != SM3_DIGEST_SIZE)
		return -1;

	if (bsdstyle)
		fprintf(fout, "%s (%s) = ", sm3name, fname);

	for (i = 0; i < hashlen; i++)
		fprintf(fout, "%02x", hash[i]);

	if (bsdstyle)
		fprintf(fout, "\n");
	else
		fprintf(fout, "  %s\n", fname);

	return 0;
}

/*
 * bsd style: "prefix (filename) = hex_hash"
 *  example:
 *  SM3 (/bin/ls) = d7c20ba3d32b42a946f17ff80f124e4a318846f37f14b9a926f0c9f1b3a76e12
 *
 * general style: "hex_hash  filename"
 *  example:
 *  d7c20ba3d32b42a946f17ff80f124e4a318846f37f14b9a926f0c9f1b3a76e12  /bin/ls
*/
static int splite_fname_hex_hash(char *buf, int len_buf, char *fname, int len_fname,
                                         char *hash,  int len_hash)
{
	int ret = -1;
	char *p_fname = NULL;
	char *ptr = NULL;
	char *tail = NULL;
	const char *prefix = "SM3 (";
	int len_prefix = strlen(prefix);
	int len = 0;

	if (!buf || len_buf <= 0 || !fname || len_fname <= 0 || !hash || len_hash < SM3_DIGEST_SIZE * 2)
		return ret;

	tail = buf + len_buf;

	if (strncmp(buf, prefix, len_prefix) == 0) {
		p_fname = buf + len_prefix;
		ptr = strrchr(buf, '=');
		if (ptr != NULL && p_fname < ptr - 2
				&& tail - (ptr + 2) == SM3_DIGEST_SIZE * 2) {
			memcpy(hash, ptr + 2, SM3_DIGEST_SIZE * 2);

			len = ptr - 2 - p_fname;
			if (len > len_fname) {
				fprintf(stderr, "file name buf too small!\n");
			} else {
				memcpy(fname, p_fname, len);
				ret = 0;
			}
		}
	} else if ((ptr=strstr(buf, "  ")) != NULL) {
		p_fname = ptr + 2;
		if (ptr - buf == SM3_DIGEST_SIZE * 2 && p_fname < tail) {
			memcpy(hash, buf, SM3_DIGEST_SIZE * 2);

			len = tail - p_fname;
			if (len > len_fname) {
				fprintf(stderr, "file name buf too small!\n");
			} else {
				memcpy(fname, p_fname, len);
				ret = 0;
			}
		}
	}

	return ret;
}

static int check_sm3(const char *outname)
{
	FILE *f = NULL;

	if (outname[0] == '-' && outname[1] == '\0')
		f = stdin;
	else
		f = fopen(outname, "rb");

	if (!f) {
		fprintf(stderr, "Could not open `%s': %s\n", outname,
			strerror(errno));
		exit(-1);
	}

	while (!feof(f) && !ferror(f)) {
		char line[LINE_MAX] = { 0 };
		char fname[NAME_MAX] = { 0 };
		char hex_hash[SM3_DIGEST_SIZE * 2 + 1] = { 0 };
		unsigned char old_hash[SM3_DIGEST_SIZE] = { 0 };
		unsigned char new_hash[SM3_DIGEST_SIZE] = { 0 };
		char *s = NULL;
		int hash_len = 0;
		int i;
		unsigned int c;
		int len = 0;
		int ret = 0;

		s = fgets(line, sizeof(line), f);
		if (s == NULL)
			break;
		len = strlen(line);
		if (line[len-1] == '\n')
			line[len-1] = '\0';

		ret = splite_fname_hex_hash(line, strlen(line), fname, sizeof(fname)-1,
                                            hex_hash, sizeof(hex_hash)-1);
		if (ret < 0)
			continue;

		len = strlen(hex_hash);
		hash_len = len/2;
		if (len%2 != 0 || hash_len != SM3_DIGEST_SIZE){
			fprintf(stderr, "%s digest size err!\n", fname);
			continue;
		}

		for (i = 0; i < hash_len; i++) {
			sscanf(&hex_hash[i * 2], "%02x", &c);
			old_hash[i] = (unsigned char)c;
		}

		ret = sm3_file(fname, new_hash, hash_len);
		if (ret < 0) {
			fprintf(stderr, "calculate sm3 err:%s\n", fname);
			continue;
		}
		if (memcmp(old_hash, new_hash, hash_len) == 0)
			fprintf(stdout, "%s OK\n", fname);
		else
			fprintf(stdout, "%s ERROR\n", fname);

	}

	if (f != stdout)
		fclose(f);
	return 0;
}

static void usage(char **argv, int outerr)
{
	FILE *out = outerr ? stderr : stdout;
	fprintf(out, "Usage: %s [OPTION]... [FILE]...\n", argv[0]);
	fprintf(out, "\n");
	fprintf(out, "With no FILE, or when FILE is -, read standard input.\n");
	fprintf(out, "\n");
	fprintf(out,
		"  -c | --check read SM3 sums from the FILEs and check them\n");
	fprintf(out, "  --tag        create a BSD-style checksum\n");
	fprintf(out, "  --help       display this help and exit\n");
	exit(-1);
}

int main(int argc, char **argv)
{
	unsigned char hash[SM3_DIGEST_SIZE] = { 0 };
	int bsdstyle = 0;
	int check = 0;
	int c, i;

	static struct option long_options[] = {
		{"check", no_argument, 0, 'c'},
		{"help", no_argument, 0, 'h'},
		{"tag", no_argument, 0, 't'},
		{NULL, 0, NULL, 0}
	};

	opterr = 1;
	while (1) {
		int option_index = 0;

		c = getopt_long(argc, argv, "cht", long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'c':
			check = 1;
			break;
		case 't':
			bsdstyle = 1;
			break;
		case 'h':
			usage(argv, 0);
			break;
		case '?':
			usage(argv, 1);
			break;
		}
	}

	if (optind == argc)
		argv[argc++] = (char *)"-";

	if (!check) {
		for (i = optind; i < argc; ++i) {
			if (sm3_file(argv[i], hash, sizeof(hash)) < 0) {
				fprintf(stderr, "calculate sm3 err:%s\n",
					argv[i]);
				continue;
			}
			print_out(bsdstyle, stdout, argv[i], hash,
				  sizeof(hash));
		}
	} else {
		check_sm3(argv[optind]);
	}

	return 0;
}
