
#ifndef _SHA224_H_
#define _SHA224_H_

typedef unsigned int SHA224_word;
typedef unsigned long SHA224_size;

typedef struct SHA224 SHA224;

struct SHA224
{
	SHA224_word schedule[64];
	SHA224_word values[8];
	char buffer[64];
	SHA224_size size;
	short upto;
};

void SHA224_init(SHA224* s);
void SHA224_update(SHA224* s, const char* data, SHA224_size len);
void SHA224_digest(SHA224* s, char* data);

#endif
