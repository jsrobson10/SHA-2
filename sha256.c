
#include <stdio.h>
#include <stddef.h>

#include "sha256.h"

typedef SHA256_word word;

/* CONSTANTS */

// square roots of first 8 primes
const word SHA256_INIT[] =
{
	0b01101010000010011110011001100111, 0b10111011011001111010111010000101,
	0b00111100011011101111001101110010, 0b10100101010011111111010100111010,
	0b01010001000011100101001001111111, 0b10011011000001010110100010001100,
	0b00011111100000111101100110101011, 0b01011011111000001100110100011001,
};

// cube roots of first 64 primes
const word SHA256_CONST[] =
{
	0b01000010100010100010111110011000, 0b01110001001101110100010010010001,
	0b10110101110000001111101111001111, 0b11101001101101011101101110100101,
	0b00111001010101101100001001011011, 0b01011001111100010001000111110001,
	0b10010010001111111000001010100100, 0b10101011000111000101111011010101,
	0b11011000000001111010101010011000, 0b00010010100000110101101100000001,
	0b00100100001100011000010110111110, 0b01010101000011000111110111000011,
	0b01110010101111100101110101110100, 0b10000000110111101011000111111110,
	0b10011011110111000000011010100111, 0b11000001100110111111000101110100,
	0b11100100100110110110100111000001, 0b11101111101111100100011110000110,
	0b00001111110000011001110111000110, 0b00100100000011001010000111001100,
	0b00101101111010010010110001101111, 0b01001010011101001000010010101010,
	0b01011100101100001010100111011100, 0b01110110111110011000100011011010,
	0b10011000001111100101000101010010, 0b10101000001100011100011001101101,
	0b10110000000000110010011111001000, 0b10111111010110010111111111000111,
	0b11000110111000000000101111110011, 0b11010101101001111001000101000111,
	0b00000110110010100110001101010001, 0b00010100001010010010100101100111,
	0b00100111101101110000101010000101, 0b00101110000110110010000100111000,
	0b01001101001011000110110111111100, 0b01010011001110000000110100010011,
	0b01100101000010100111001101010100, 0b01110110011010100000101010111011,
	0b10000001110000101100100100101110, 0b10010010011100100010110010000101,
	0b10100010101111111110100010100001, 0b10101000000110100110011001001011,
	0b11000010010010111000101101110000, 0b11000111011011000101000110100011,
	0b11010001100100101110100000011001, 0b11010110100110010000011000100100,
	0b11110100000011100011010110000101, 0b00010000011010101010000001110000,
	0b00011001101001001100000100010110, 0b00011110001101110110110000001000,
	0b00100111010010000111011101001100, 0b00110100101100001011110010110101,
	0b00111001000111000000110010110011, 0b01001110110110001010101001001010,
	0b01011011100111001100101001001111, 0b01101000001011100110111111110011,
	0b01110100100011111000001011101110, 0b01111000101001010110001101101111,
	0b10000100110010000111100000010100, 0b10001100110001110000001000001000,
	0b10010000101111101111111111111010, 0b10100100010100000110110011101011,
	0b10111110111110011010001111110111, 0b11000110011100010111100011110010,
};

/* COMPOUND OPERATIONS */

word SHA256_op_sigma0(word x)
{
	word a = (x >> 7) | (x << 25);
	word b = (x >> 18) | (x << 14);
	word c = x >> 3;

	return a ^ b ^ c;
}

word SHA256_op_sigma1(word x)
{
	word a = (x >> 17) | (x << 15);
	word b = (x >> 19) | (x << 13);
	word c = x >> 10;

	return a ^ b ^ c;
}

word SHA256_op_usigma0(word x)
{
	word a = (x >> 2) | (x << 30);
	word b = (x >> 13) | (x << 19);
	word c = (x >> 22) | (x << 10);

	return a ^ b ^ c;
}

word SHA256_op_usigma1(word x)
{
	word a = (x >> 6) | (x << 26);
	word b = (x >> 11) | (x << 21);
	word c = (x >> 25) | (x << 7);

	return a ^ b ^ c;
}

word SHA256_op_choice(word a, word b, word c)
{
	return (a & b) ^ (~a & c);
}

word SHA256_op_majority(word a, word b, word c)
{
	return (a & b) ^ (a & c) ^ (b & c);
}

/* FUNCTIONS */

void SHA256_op_copy(void* to, const void* from, size_t len)
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
	word schedule[64];

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
		schedule[i] = SHA256_op_sigma1(schedule[i - 2]) + schedule[i - 7] + SHA256_op_sigma0(schedule[i - 15]) + schedule[i - 16];
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
		word w1 = SHA256_op_usigma1(words[4]) + SHA256_op_choice(words[4], words[5], words[6]) + words[7] + SHA256_CONST[i] + schedule[i];
		word w2 = SHA256_op_usigma0(words[0]) + SHA256_op_majority(words[0], words[1], words[2]);

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

void SHA256_init(SHA256* s)
{
	SHA256_op_copy(s->words, SHA256_INIT, sizeof(word) * 8);

	s->upto = 0;
	s->size = 0;
}

void SHA256_update(SHA256* s, const char* data, size_t len)
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
	size_t upto = s->upto;
	size_t size = s->size + upto;
	size_t size_bits = size * 8;

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

		buffer[i4  ] = (s->words[i] >> 24) & 255;
		buffer[i4+1] = (s->words[i] >> 16) & 255;
		buffer[i4+2] = (s->words[i] >> 8 ) & 255;
		buffer[i4+3] = (s->words[i]      ) & 255;
	}
}
