
#include "sha224.h"

typedef SHA224_word word;

/* CONSTANTS */

const word SHA224_INIT[] =
{
	0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
};

// cube roots of the first 64 primes
const word SHA224_CONST[] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,   
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, 
};

/* COMPOUND OPERATIONS */

word SHA224_op_sigma0(word x)
{
	word a = (x >> 7) | (x << 25);
	word b = (x >> 18) | (x << 14);
	word c = x >> 3;

	return a ^ b ^ c;
}

word SHA224_op_sigma1(word x)
{
	word a = (x >> 17) | (x << 15);
	word b = (x >> 19) | (x << 13);
	word c = x >> 10;

	return a ^ b ^ c;
}

word SHA224_op_usigma0(word x)
{
	word a = (x >> 2) | (x << 30);
	word b = (x >> 13) | (x << 19);
	word c = (x >> 22) | (x << 10);

	return a ^ b ^ c;
}

word SHA224_op_usigma1(word x)
{
	word a = (x >> 6) | (x << 26);
	word b = (x >> 11) | (x << 21);
	word c = (x >> 25) | (x << 7);

	return a ^ b ^ c;
}

word SHA224_op_choice(word a, word b, word c)
{
	return (a & b) ^ (~a & c);
}

word SHA224_op_majority(word a, word b, word c)
{
	return (a & b) ^ (a & c) ^ (b & c);
}

/* FUNCTIONS */

void SHA224_op_copy(void* to, const void* from, SHA224_size len)
{
	void* end = to + len;

	while(to < end)
	{
		*(char*)to = *(const char*)from;

		to += 1;
		from += 1;
	}
}

void SHA224_op_process_chunk(SHA224* s)
{
	word* schedule = s->schedule;
	char* schedule_c = (char*)schedule;

	// copy all the data over to the schedule accounting for endianness
	for(int i = 0; i < 16; i++)
	{
		int i4 = i * 4;

		word w1 = s->buffer[i4] & 255;
		word w2 = s->buffer[i4+1] & 255;
		word w3 = s->buffer[i4+2] & 255;
		word w4 = s->buffer[i4+3] & 255;

		schedule[i] = (w1 << 24) | (w2 << 16) | (w3 << 8) | w4;
	}

	// fill in the last 64 words of the message schedule
	for(int i = 16; i < 64; i++)
	{
		schedule[i] = SHA224_op_sigma1(schedule[i - 2]) + schedule[i - 7] + SHA224_op_sigma0(schedule[i - 15]) + schedule[i - 16];
	}

	word words[8];

	// make a copy of words
	for(int i = 0; i < 8; i++)
	{
		words[i] = s->words[i];
	}

	// compress the message schedule
	for(int i = 0; i < 64; i++)
	{
		word w1 = SHA224_op_usigma1(words[4]) + SHA224_op_choice(words[4], words[5], words[6]) + words[7] + SHA224_CONST[i] + schedule[i];
		word w2 = SHA224_op_usigma0(words[0]) + SHA224_op_majority(words[0], words[1], words[2]);

		// move the words down
		for(int i = 7; i > 0; i--)
		{
			words[i] = words[i-1];
		}

		// change the words
		words[0] = w1 + w2;
		words[4] += w1;
	}

	// add the new words to the initial values
	for(int i = 0; i < 8; i++)
	{
		s->words[i] += words[i];
	}
}

void SHA224_init(SHA224* s)
{
	SHA224_op_copy(s->words, SHA224_INIT, sizeof(word) * 8);

	s->upto = 0;
	s->size = 0;
}

void SHA224_update(SHA224* s, const char* data, SHA224_size len)
{
	// process complete blocks as we update to make this streamable
	while(len + s->upto >= sizeof(s->buffer))
	{
		// calculate the amount of data to add to the buffer but dont overflow
		int a = sizeof(s->buffer) - s->upto;

		if(len < a)
		{
			a = len;
		}

		// move the data into the buffer
		SHA224_op_copy(s->buffer + s->upto, data, a);

		SHA224_op_process_chunk(s);

		len -= a;
		data += a;

		s->upto = 0;
		s->size += sizeof(s->buffer);
	}

	// add the smaller data to the end of the buffer
	SHA224_op_copy(s->buffer + s->upto, data, len);
	s->upto += len;
}

void SHA224_digest(SHA224* s, char* buffer)
{
	// pad the last chunk
	SHA224_size upto = s->upto;
	SHA224_size size = s->size + upto;
	SHA224_size size_bits = size * 8;

	// add a 1 after the data
	s->buffer[upto] = 1 << 7;

	if(upto < 56)
	{
		// fill with zeros
		for(int i = upto + 1; i < 56; i++)
		{
			s->buffer[i] = (char)0;
		}
	}

	else
	{
		// fill with zeros
		for(int i = upto + 1; i < 64; i++)
		{
			s->buffer[i] = (char)0;
		}

		// process the first padded chunk
		SHA224_op_process_chunk(s);

		// fill the next buffer with zeros
		for(int i = 0; i < 56; i++)
		{
			s->buffer[i] = (char)0;
		}
	}

	// add the size
	for(int i = 63; i >= 56; i--)
	{
		s->buffer[i] = size_bits & 255;
		size_bits >>= 8;
	}

	// process the final padded chunk
	SHA224_op_process_chunk(s);

	// copy the words into the buffer
	for(int i = 0; i < 7; i++)
	{
		int i4 = i * 4;

		buffer[i4  ] = (s->words[i] >> 24) & 255;
		buffer[i4+1] = (s->words[i] >> 16) & 255;
		buffer[i4+2] = (s->words[i] >> 8 ) & 255;
		buffer[i4+3] = (s->words[i]      ) & 255;
	}
}
