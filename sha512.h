
#ifndef _SHA512_H_
#define _SHA512_H_

typedef unsigned long SHA512_word;
typedef unsigned __int128 SHA512_size;

typedef struct SHA512 SHA512;

struct SHA512
{
	SHA512_word schedule[80];
	SHA512_word values[8];
	char buffer[128];
	SHA512_size size;
	short upto;
};

void SHA512_init(SHA512* s);
void SHA512_update(SHA512* s, const char* data, SHA512_size len);
void SHA512_digest(SHA512* s, char* data);

#endif
