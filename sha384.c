
#include "sha384.h"

/* CONSTANTS */

const SHA384_word SHA384_INIT[] =
{
	0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
	0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
};

// cube roots of the first 80 primes
const SHA384_word SHA384_CONST[] =
{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

/* COMPOUND OPERATIONS */

SHA384_word SHA384_op_sigma0(SHA384_word x)
{
	SHA384_word a = (x >> 1) | (x << 63);
	SHA384_word b = (x >> 8) | (x << 56);
	SHA384_word c = x >> 7;

	return a ^ b ^ c;
}

SHA384_word SHA384_op_sigma1(SHA384_word x)
{
	SHA384_word a = (x >> 19) | (x << 45);
	SHA384_word b = (x >> 61) | (x << 3);
	SHA384_word c = x >> 6;

	return a ^ b ^ c;
}

SHA384_word SHA384_op_usigma0(SHA384_word x)
{
	SHA384_word a = (x >> 28) | (x << 36);
	SHA384_word b = (x >> 34) | (x << 30);
	SHA384_word c = (x >> 39) | (x << 25);

	return a ^ b ^ c;
}

SHA384_word SHA384_op_usigma1(SHA384_word x)
{
	SHA384_word a = (x >> 14) | (x << 50);
	SHA384_word b = (x >> 18) | (x << 46);
	SHA384_word c = (x >> 41) | (x << 23);

	return a ^ b ^ c;
}

SHA384_word SHA384_op_choice(SHA384_word a, SHA384_word b, SHA384_word c)
{
	return (a & b) ^ (~a & c);
}

SHA384_word SHA384_op_majority(SHA384_word a, SHA384_word b, SHA384_word c)
{
	return (a & b) ^ (a & c) ^ (b & c);
}

/* FUNCTIONS */

void SHA384_op_copy(void* to, const void* from, SHA384_size len)
{
	void* end = to + len;

	while(to < end)
	{
		*(char*)to = *(const char*)from;

		to += 1;
		from += 1;
	}
}

void SHA384_op_process_chunk(SHA384* s)
{
	SHA384_word* schedule = s->schedule;

	// copy all the data over to the schedule accounting for endianness
	for(int i = 0; i < 16; i++)
	{
		int i8 = i * 8;

		SHA384_word w1 = s->buffer[i8] & 255;
		SHA384_word w2 = s->buffer[i8+1] & 255;
		SHA384_word w3 = s->buffer[i8+2] & 255;
		SHA384_word w4 = s->buffer[i8+3] & 255;
		SHA384_word w5 = s->buffer[i8+4] & 255;
		SHA384_word w6 = s->buffer[i8+5] & 255;
		SHA384_word w7 = s->buffer[i8+6] & 255;
		SHA384_word w8 = s->buffer[i8+7] & 255;

		schedule[i] = (w1 << 56) | (w2 << 48) | (w3 << 40) | (w4 << 32) | (w5 << 24) | (w6 << 16) | (w7 << 8) | w8;
	}

	// fill in the last 80 words of the message schedule
	for(int i = 16; i < 80; i++)
	{
		SHA384_word s1 = schedule[i - 2];
		SHA384_word s2 = schedule[i - 15];
		SHA384_word s3 = (s2 >> 1) ^ (s2 << 63) ^ (s2 >> 8) ^ (s2 << 56) ^ (s2 >> 7); // sigma0
		SHA384_word s4 = (s1 >> 19) ^ (s1 << 45) ^ (s1 >> 61) ^ (s1 << 3) ^ (s1 >> 6); // sigma1
		schedule[i] = s3 + s4 + schedule[i - 7] + schedule[i - 16];
	}

	// make a copy of the values
	SHA384_word a = s->values[0];
	SHA384_word b = s->values[1];
	SHA384_word c = s->values[2];
	SHA384_word d = s->values[3];
	SHA384_word e = s->values[4];
	SHA384_word f = s->values[5];
	SHA384_word g = s->values[6];
	SHA384_word h = s->values[7];

	// compress the message schedule
	for(int i = 0; i < 80; i++)
	{
		SHA384_word s1 = (a >> 28) ^ (a << 36) ^ (a >> 34) ^ (a << 30) ^ (a >> 39) ^ (a << 25); // usigma0
		SHA384_word s2 = (e >> 14) ^ (e << 50) ^ (e >> 18) ^ (e << 46) ^ (e >> 41) ^ (e << 23); // usigma1
		SHA384_word t1 = s2 + ((e & f) ^ (~e & g)) + h + SHA384_CONST[i] + schedule[i];
		SHA384_word t2 = s1 + ((a & b) ^ (a & c) ^ (b & c));

		// move the values down and change them
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
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

void SHA384_init(SHA384* s)
{
	SHA384_op_copy(s->values, SHA384_INIT, sizeof(SHA384_word) * 8);

	s->upto = 0;
	s->size = 0;
}

void SHA384_update(SHA384* s, const char* data, SHA384_size len)
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
		SHA384_op_copy(s->buffer + s->upto, data, a);

		SHA384_op_process_chunk(s);

		len -= a;
		data += a;

		s->upto = 0;
		s->size += sizeof(s->buffer);
	}

	// add the smaller data to the end of the buffer
	SHA384_op_copy(s->buffer + s->upto, data, len);
	s->upto += len;
}

void SHA384_digest(SHA384* s, char* buffer)
{
	// pad the last chunk
	SHA384_size upto = s->upto;
	SHA384_size size = s->size + upto;
	SHA384_size size_bits = size * 8;

	// add a 1 after the data
	s->buffer[upto] = 1 << 7;

	if(upto < 112)
	{
		// fill with zeros
		for(int i = upto + 1; i < 112; i++)
		{
			s->buffer[i] = (char)0;
		}
	}

	else
	{
		// fill with zeros
		for(int i = upto + 1; i < 128; i++)
		{
			s->buffer[i] = (char)0;
		}

		// process the first padded chunk
		SHA384_op_process_chunk(s);

		// fill the next buffer with zeros
		for(int i = 0; i < 112; i++)
		{
			s->buffer[i] = (char)0;
		}
	}

	// add the size
	for(int i = 127; i >= 112; i--)
	{
		s->buffer[i] = size_bits & 255;
		size_bits >>= 8;
	}

	// process the final padded chunk
	SHA384_op_process_chunk(s);

	// copy the words into the buffer
	for(int i = 0; i < 6; i++)
	{
		int i8 = i * 8;

		buffer[i8  ] = (s->values[i] >> 56) & 255;
		buffer[i8+1] = (s->values[i] >> 48) & 255;
		buffer[i8+2] = (s->values[i] >> 40) & 255;
		buffer[i8+3] = (s->values[i] >> 32) & 255;
		buffer[i8+4] = (s->values[i] >> 24) & 255;
		buffer[i8+5] = (s->values[i] >> 16) & 255;
		buffer[i8+6] = (s->values[i] >> 8 ) & 255;
		buffer[i8+7] = (s->values[i]      ) & 255;
	}
}
