
#ifndef _SHA256_H_
#define _SHA256_H_

typedef unsigned int SHA256_word;
typedef unsigned long SHA256_size;

typedef struct SHA256 SHA256;

struct SHA256
{
	SHA256_word schedule[64];
	SHA256_word words[8];
	char buffer[64];
	SHA256_size size;
	short upto;
};

void SHA256_init(SHA256* s);
void SHA256_update(SHA256* s, const char* data, SHA256_size len);
void SHA256_digest(SHA256* s, char* data);

#endif
