
#ifdef T_sha1
#include "sha1.h"
#define SHA_init SHA1_init
#define SHA_update SHA1_update
#define SHA_digest SHA1_digest
#define SHA SHA1
#define SIZE 20
#endif

#ifdef T_sha224
#include "sha224.h"
#define SHA_init SHA224_init
#define SHA_update SHA224_update
#define SHA_digest SHA224_digest
#define SHA SHA224
#define SIZE 28
#endif

#ifdef T_sha256
#include "sha256.h"
#define SHA_init SHA256_init
#define SHA_update SHA256_update
#define SHA_digest SHA256_digest
#define SHA SHA256
#define SIZE 32
#endif

#ifdef T_sha384
#include "sha384.h"
#define SHA_init SHA384_init
#define SHA_update SHA384_update
#define SHA_digest SHA384_digest
#define SHA SHA384
#define SIZE 48
#endif

#ifdef T_sha512
#include "sha512.h"
#define SHA_init SHA512_init
#define SHA_update SHA512_update
#define SHA_digest SHA512_digest
#define SHA SHA512
#define SIZE 64
#endif

#include <stdio.h>
#include <string.h>

char buffer[1024];

void display_hex(const char* buff, size_t len)
{
	const char HEX[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

	for(size_t i = 0; i < len; i++)
	{
		char c = buff[i];

		printf("%c%c", HEX[(c >> 4) & 15], HEX[c & 15]);
	}
}

void display_bin(const char* num, size_t len)
{
	for(int i = len - 1; i >= 0; i--)
	{
		for(int j = 7; j >= 0; j--)
		{
			printf("%c", '0' + ((num[i] >> j) & 1));
		}
	}
}

SHA sha;

int main(int cargs, const char** vargs)
{
	freopen(NULL, "rb", stdin);
	
	SHA_init(&sha);

	if(cargs == 1)
	{
		size_t len;

		while((len = fread(buffer, 1, sizeof(buffer), stdin)))
		{
			SHA_update(&sha, buffer, len);
		}
	}

	else
	{
		for(int i = 1; i < cargs - 1; i++)
		{
			SHA_update(&sha, vargs[i], strlen(vargs[i]));
			SHA_update(&sha, " ", 1);
		}

		SHA_update(&sha, vargs[cargs - 1], strlen(vargs[cargs - 1]));
	}

	SHA_digest(&sha, buffer);
	display_hex(buffer, SIZE);

	printf("\n");
}
