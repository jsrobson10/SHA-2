
#include "sha1.h"

typedef SHA1_word word;

/* CONSTANTS */

const word SHA1_INIT[] =
{
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
};

const word SHA1_CONST[] =
{
	0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6,
};

/* OPERATIONS */

word SHA1_op_f(int t, word a, word b, word c)
{
	if(t < 20)
	{
		return (a & b) ^ (~a & c);
	}

	if(t >= 40 && t < 60)
	{
		return (a & b) ^ (a & c) ^ (b & c);
	}

	return a ^ b ^ c;
}

/* FUNCTIONS */

void SHA1_op_copy(void* to, const void* from, SHA1_size len)
{
	void* end = to + len;

	while(to < end)
	{
		*(char*)to = *(const char*)from;

		to += 1;
		from += 1;
	}
}

void SHA1_op_process_chunk(SHA1* s)
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
	for(int i = 16; i < 80; i++)
	{
		schedule[i] = schedule[i - 3] ^ schedule[i - 8] ^ schedule[i - 14] ^ schedule[i - 16];
		schedule[i] = (schedule[i] << 1) | (schedule[i] >> 31);
	}

	word words[5];

	// make a copy of words
	for(int i = 0; i < 5; i++)
	{
		words[i] = s->words[i];
	}

	// compress the message schedule
	for(int i = 0; i < 80; i++)
	{
		word w = ((words[0] << 5) | (words[0] >> 27)) + SHA1_op_f(i, words[1], words[2], words[3]) + words[4] + SHA1_CONST[i / 20] + schedule[i];
	
		words[4] = words[3];
		words[3] = words[2];
		words[2] = (words[1] << 30) | (words[1] >> 2);
		words[1] = words[0];
		words[0] = w;
	}

	// add the new words to the initial values
	for(int i = 0; i < 5; i++)
	{
		s->words[i] += words[i];
	}
}

void SHA1_init(SHA1* s)
{
	SHA1_op_copy(s->words, SHA1_INIT, sizeof(SHA1_INIT));

	s->upto = 0;
	s->size = 0;
}

void SHA1_update(SHA1* s, const char* data, SHA1_size len)
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
		SHA1_op_copy(s->buffer + s->upto, data, a);

		SHA1_op_process_chunk(s);

		len -= a;
		data += a;

		s->upto = 0;
		s->size += sizeof(s->buffer);
	}

	// add the smaller data to the end of the buffer
	SHA1_op_copy(s->buffer + s->upto, data, len);
	s->upto += len;
}

void SHA1_digest(SHA1* s, char* buffer)
{
	// pad the last chunk
	SHA1_size upto = s->upto;
	SHA1_size size = s->size + upto;
	SHA1_size size_bits = size * 8;

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
		SHA1_op_process_chunk(s);

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
	SHA1_op_process_chunk(s);

	// copy the words into the buffer
	for(int i = 0; i < 5; i++)
	{
		int i4 = i * 4;

		buffer[i4  ] = (s->words[i] >> 24) & 255;
		buffer[i4+1] = (s->words[i] >> 16) & 255;
		buffer[i4+2] = (s->words[i] >> 8 ) & 255;
		buffer[i4+3] = (s->words[i]      ) & 255;
	}
}
