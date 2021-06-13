
#ifndef _SHA256_H_
#define _SHA256_H_

#include <stddef.h>

typedef struct SHA256 SHA256;
typedef unsigned int SHA256_word;

struct SHA256
{
	SHA256_word words[8];
	char buffer[64];
	size_t size;
	short upto;
};

void SHA256_init(SHA256* s);
void SHA256_update(SHA256* s, const char* data, size_t len);
void SHA256_digest(SHA256* s, char* data);

#endif
