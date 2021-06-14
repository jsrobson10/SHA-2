
#ifndef _SHA384_H_
#define _SHA384_H_

typedef unsigned long SHA384_word;
typedef unsigned __int128 SHA384_size;

typedef struct SHA384 SHA384;

struct SHA384
{
	SHA384_word schedule[80];
	SHA384_word values[8];
	char buffer[128];
	SHA384_size size;
	short upto;
};

void SHA384_init(SHA384* s);
void SHA384_update(SHA384* s, const char* data, SHA384_size len);
void SHA384_digest(SHA384* s, char* data);

#endif
