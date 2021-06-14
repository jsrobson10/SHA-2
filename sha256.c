
#include "sha256.h"

/* CONSTANTS */

// square roots of first 8 primes
const SHA256_word SHA256_INIT[] =
{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

// cube roots of first 64 primes
const SHA256_word SHA256_CONST[] =
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

SHA256_word SHA256_op_sigma0(SHA256_word x)
{
	SHA256_word a = (x >> 7) | (x << 25);
	SHA256_word b = (x >> 18) | (x << 14);
	SHA256_word c = x >> 3;

	return a ^ b ^ c;
}

SHA256_word SHA256_op_sigma1(SHA256_word x)
{
	SHA256_word a = (x >> 17) | (x << 15);
	SHA256_word b = (x >> 19) | (x << 13);
	SHA256_word c = x >> 10;

	return a ^ b ^ c;
}

SHA256_word SHA256_op_usigma0(SHA256_word x)
{
	SHA256_word a = (x >> 2) | (x << 30);
	SHA256_word b = (x >> 13) | (x << 19);
	SHA256_word c = (x >> 22) | (x << 10);

	return a ^ b ^ c;
}

SHA256_word SHA256_op_usigma1(SHA256_word x)
{
	SHA256_word a = (x >> 6) | (x << 26);
	SHA256_word b = (x >> 11) | (x << 21);
	SHA256_word c = (x >> 25) | (x << 7);

	return a ^ b ^ c;
}

SHA256_word SHA256_op_choice(SHA256_word a, SHA256_word b, SHA256_word c)
{
	return (a & b) ^ (~a & c);
}

SHA256_word SHA256_op_majority(SHA256_word a, SHA256_word b, SHA256_word c)
{
	return (a & b) ^ (a & c) ^ (b & c);
}

/* FUNCTIONS */

void SHA256_op_copy(void* to, const void* from, SHA256_size len)
{
	void* end = to + len;

	while(to < end)
	{
		*(char*)to = *(const char*)from;

		to += 1;
		from += 1;
	}
}

void SHA256_op_process_chunk(SHA256* s)
{
	SHA256_word* schedule = s->schedule;

	// copy all the data over to the schedule accounting for endianness
	for(int i = 0; i < 16; i++)
	{
		int i4 = i * 4;

		SHA256_word w1 = s->buffer[i4] & 255;
		SHA256_word w2 = s->buffer[i4+1] & 255;
		SHA256_word w3 = s->buffer[i4+2] & 255;
		SHA256_word w4 = s->buffer[i4+3] & 255;

		schedule[i] = (w1 << 24) | (w2 << 16) | (w3 << 8) | w4;
	}

	// fill in the last 64 words of the message schedule
	for(int i = 16; i < 64; i++)
	{
		schedule[i] = SHA256_op_sigma1(schedule[i - 2]) + schedule[i - 7] + SHA256_op_sigma0(schedule[i - 15]) + schedule[i - 16];
	}

	// make a copy of the values
	SHA256_word a = s->values[0];
	SHA256_word b = s->values[1];
	SHA256_word c = s->values[2];
	SHA256_word d = s->values[3];
	SHA256_word e = s->values[4];
	SHA256_word f = s->values[5];
	SHA256_word g = s->values[6];
	SHA256_word h = s->values[7];

	// compress the message schedule
	for(int i = 0; i < 64; i++)
	{
		SHA256_word w1 = SHA256_op_usigma1(e) + SHA256_op_choice(e, f, g) + h + SHA256_CONST[i] + schedule[i];
		SHA256_word w2 = SHA256_op_usigma0(a) + SHA256_op_majority(a, b, c);

		// move the values down and change them
		h = g;
		g = f;
		f = e;
		e = w1;
		d = c;
		c = b;
		b = w1 + w2;
	}

	// add the new values to the initial values
	s->values[0] += a;
	s->values[1] += b;
	s->values[2] += c;
	s->values[3] += d;
	s->values[4] += e;
	s->values[5] += f;
	s->values[6] += g;
	s->values[7] += h;
}

void SHA256_init(SHA256* s)
{
	SHA256_op_copy(s->values, SHA256_INIT, sizeof(SHA256_word) * 8);

	s->upto = 0;
	s->size = 0;
}

void SHA256_update(SHA256* s, const char* data, SHA256_size len)
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
		SHA256_op_copy(s->buffer + s->upto, data, a);

		SHA256_op_process_chunk(s);

		len -= a;
		data += a;

		s->upto = 0;
		s->size += sizeof(s->buffer);
	}

	// add the smaller data to the end of the buffer
	SHA256_op_copy(s->buffer + s->upto, data, len);
	s->upto += len;
}

void SHA256_digest(SHA256* s, char* buffer)
{
	// pad the last chunk
	SHA256_size upto = s->upto;
	SHA256_size size = s->size + upto;
	SHA256_size size_bits = size * 8;

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
		SHA256_op_process_chunk(s);

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
	SHA256_op_process_chunk(s);

	// copy the words into the buffer
	for(int i = 0; i < 8; i++)
	{
		int i4 = i * 4;

		buffer[i4  ] = (s->values[i] >> 24) & 255;
		buffer[i4+1] = (s->values[i] >> 16) & 255;
		buffer[i4+2] = (s->values[i] >> 8 ) & 255;
		buffer[i4+3] = (s->values[i]      ) & 255;
	}
}
