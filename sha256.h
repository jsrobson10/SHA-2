
#ifndef _SHA256_H_
#define _SHA256_H_

#include <stddef.h>

typedef struct sha256 sha256;
typedef unsigned int sha256_word;

struct sha256
{
	sha256_word words[8];
	char buffer[64];
	size_t size;
	short upto;
};

void sha256_init(sha256* s);
void sha256_update(sha256* s, const char* data, size_t len);
void sha256_digest(sha256* s, char* data);

sha256_word sha256_sigma0(sha256_word x);
sha256_word sha256_sigma1(sha256_word x);
sha256_word sha256_usigma0(sha256_word x);
sha256_word sha256_usigma1(sha256_word x);

#endif
