
#ifndef _SHA1_H_
#define _SHA1_H_

typedef unsigned int SHA1_word;
typedef unsigned long SHA1_size;

typedef struct SHA1 SHA1;

struct SHA1
{
	SHA1_word schedule[80];
	SHA1_word values[5];
	char buffer[64];
	SHA1_size size;
	short upto;
};

void SHA1_init(SHA1* s);
void SHA1_update(SHA1* s, const char* data, SHA1_size len);
void SHA1_digest(SHA1* s, char* data);

#endif
