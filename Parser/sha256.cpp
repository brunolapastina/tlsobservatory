#include <cstdlib>
#include <cstring>
#include "sha256.hpp"

#ifndef GET_UINT32_BE
#ifdef _MSC_VER
#define GET_UINT32_BE(n,b,i)  (n) = _byteswap_ulong(*((unsigned int*)(b + i)))
#else
#define GET_UINT32_BE(n,b,i)  (n) = __builtin_bswap32(*((unsigned int*)(b + i)))
#endif
#endif

#ifndef PUT_UINT32_BE
#ifdef _MSC_VER
#define PUT_UINT32_BE(n,b,i)  *((unsigned int*)(b + i)) = _byteswap_ulong(n)
#else
#define PUT_UINT32_BE(n,b,i)  *((unsigned int*)(b + i)) = __builtin_bswap32(n)
#endif
#endif


void SHA256::update(const unsigned char *input, size_t ilen) noexcept
{
	if( ilen == 0 )
		return;

   uint32_t left = total_[0] & 0x3F;
   size_t fill = 64 - left;

	total_[0] += (uint32_t) ilen;
	total_[0] &= 0xFFFFFFFF;

	if( total_[0] < (uint32_t) ilen )
		total_[1]++;

	if( left && ilen >= fill )
	{
		memcpy( (buffer_ + left), input, fill );
		process( buffer_ );
		input += fill;
		ilen  -= fill;
		left = 0;
	}

	while( ilen >= 64 )
	{
		process( input );
		input += 64;
		ilen  -= 64;
	}

	if( ilen > 0 )
		memcpy( (buffer_ + left), input, ilen );
}


SHA256Hash SHA256::finish() noexcept
{
	// Add padding: 0x80 then 0x00 until 8 bytes remain for the length
   uint32_t used = total_[0] & 0x3F;

	buffer_[used++] = 0x80;

	if( used <= 56 )
	{	// Enough room for padding + length in current block
		memset( buffer_ + used, 0, 56 - used );
	}
	else
	{	// We'll need an extra block
		memset( buffer_ + used, 0, 64 - used );
		process( buffer_ );
		memset( buffer_, 0, 56 );
	}

	// Add message length
   uint32_t high = ( total_[0] >> 29 ) | ( total_[1] <<  3 );
   uint32_t low  = ( total_[0] <<  3 );

	PUT_UINT32_BE( high, buffer_, 56 );
   PUT_UINT32_BE( low,  buffer_, 60 );

	process( buffer_ );

   SHA256Hash hash;

	// Output final state
   hash.packed32[0] = _byteswap_ulong(state_[0]);
   hash.packed32[1] = _byteswap_ulong(state_[1]);
   hash.packed32[2] = _byteswap_ulong(state_[2]);
   hash.packed32[3] = _byteswap_ulong(state_[3]);
   hash.packed32[4] = _byteswap_ulong(state_[4]);
   hash.packed32[5] = _byteswap_ulong(state_[5]);
   hash.packed32[6] = _byteswap_ulong(state_[6]);
   hash.packed32[7] = _byteswap_ulong(state_[7]);

   return hash;
}

static constexpr uint32_t K[] =
{
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

#define R(t)                                 \
	(                                         \
		W[t] = S1(W[(t) -  2]) + W[(t) -  7] + \
				S0(W[(t) - 15]) + W[(t) - 16]    \
	)

static constexpr inline uint32_t SHR(uint32_t x, uint32_t n)   { return (x & 0xFFFFFFFF) >> n; }
static constexpr inline uint32_t ROTR(uint32_t x, uint32_t n)  { return SHR(x, n) | (x << (32 - n)); }

static constexpr inline uint32_t S0(uint32_t x) { return ROTR(x,  7) ^ ROTR(x, 18) ^ SHR(x,  3); }
static constexpr inline uint32_t S1(uint32_t x) { return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10); }

static constexpr inline uint32_t S2(uint32_t x) { return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22); }
static constexpr inline uint32_t S3(uint32_t x) { return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25); }

static constexpr inline uint32_t F0(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (z & (x | y)); }
static constexpr inline uint32_t F1(uint32_t x, uint32_t y, uint32_t z) { return z ^ (x & (y ^ z)); }

static constexpr inline void P(uint32_t a, uint32_t b, uint32_t c, uint32_t& d, uint32_t e, uint32_t f, uint32_t g, uint32_t& h, uint32_t x, uint32_t K) 
{
   const uint32_t temp1 = (h) + S3(e) + F1((e), (f), (g)) + (K) + (x);
   const uint32_t temp2 = S2(a) + F0((a), (b), (c));
   d += temp1;
   h = temp1 + temp2;
}

void SHA256::process( const unsigned char* data ) noexcept
{
   uint32_t W[64];
   uint32_t A[8];

   A[0] = state_[0];
   A[1] = state_[1];
   A[2] = state_[2];
   A[3] = state_[3];
   A[4] = state_[4];
   A[5] = state_[5];
   A[6] = state_[6];
   A[7] = state_[7];
		

   for (unsigned int i = 0; i < 16; i++)
   {
      GET_UINT32_BE(W[i], data, 4 * i);
   }

	for (unsigned int i = 0; i < 16; i += 8 )
	{
		P( A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], W[i+0], K[i+0] );
		P( A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], W[i+1], K[i+1] );
		P( A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], W[i+2], K[i+2] );
		P( A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], W[i+3], K[i+3] );
		P( A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], W[i+4], K[i+4] );
		P( A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], W[i+5], K[i+5] );
		P( A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], W[i+6], K[i+6] );
		P( A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], W[i+7], K[i+7] );
	}

	for (unsigned int i = 16; i < 64; i += 8 )
	{
		P( A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], R(i+0), K[i+0] );
		P( A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], R(i+1), K[i+1] );
		P( A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], R(i+2), K[i+2] );
		P( A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], R(i+3), K[i+3] );
		P( A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], R(i+4), K[i+4] );
		P( A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], R(i+5), K[i+5] );
		P( A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], R(i+6), K[i+6] );
		P( A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], R(i+7), K[i+7] );
	}

   state_[0] += A[0];
   state_[1] += A[1];
   state_[2] += A[2];
   state_[3] += A[3];
   state_[4] += A[4];
   state_[5] += A[5];
   state_[6] += A[6];
   state_[7] += A[7];
}


/*
#include <immintrin.h>
#include <intrin.h>

int CheckForIntelShaExtensions()
{
   int cpuInfo[4];
   __cpuidex(cpuInfo, 7, 0);
   // Intel SHA Extensions feature bit is EBX[29]
   return (cpuInfo[1] >> 29) & 1;
}

void SHA256::process(const unsigned char* data)
{
   __m128i STATE0, STATE1;
   __m128i MSG, TMP;
   __m128i MSG0, MSG1, MSG2, MSG3;
   __m128i ABEF_SAVE, CDGH_SAVE;
   const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

   // Load initial values
   TMP = _mm_loadu_si128((const __m128i*) & state_[0]);
   STATE1 = _mm_loadu_si128((const __m128i*) & state_[4]);


   TMP = _mm_shuffle_epi32(TMP, 0xB1);          // CDAB
   STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);    // EFGH
   STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);    // ABEF
   STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0); // CDGH

   // Save current state
   ABEF_SAVE = STATE0;
   CDGH_SAVE = STATE1;

   // Rounds 0-3
   MSG = _mm_loadu_si128((const __m128i*) (data + 0));
   MSG0 = _mm_shuffle_epi8(MSG, MASK);
   MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
   STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
   MSG = _mm_shuffle_epi32(MSG, 0x0E);
   STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

   // Rounds 4-7
   MSG1 = _mm_loadu_si128((const __m128i*) (data + 16));
   MSG1 = _mm_shuffle_epi8(MSG1, MASK);
   MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
   STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
   MSG = _mm_shuffle_epi32(MSG, 0x0E);
   STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
   MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

   // Rounds 8-11
   MSG2 = _mm_loadu_si128((const __m128i*) (data + 32));
   MSG2 = _mm_shuffle_epi8(MSG2, MASK);
   MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
   STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
   MSG = _mm_shuffle_epi32(MSG, 0x0E);
   STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
   MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

   // Rounds 12-15
   MSG3 = _mm_loadu_si128((const __m128i*) (data + 48));
   MSG3 = _mm_shuffle_epi8(MSG3, MASK);
   MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
   STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
   TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
   MSG0 = _mm_add_epi32(MSG0, TMP);
   MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
   MSG = _mm_shuffle_epi32(MSG, 0x0E);
   STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
   MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

   // Rounds 16-19
   MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
   STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
   TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
   MSG1 = _mm_add_epi32(MSG1, TMP);
   MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
   MSG = _mm_shuffle_epi32(MSG, 0x0E);
   STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
   MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

   // Rounds 20-23
   MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
   STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
   TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
   MSG2 = _mm_add_epi32(MSG2, TMP);
   MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
   MSG = _mm_shuffle_epi32(MSG, 0x0E);
   STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
   MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

   // Rounds 24-27
   MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
   STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
   TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
   MSG3 = _mm_add_epi32(MSG3, TMP);
   MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
   MSG = _mm_shuffle_epi32(MSG, 0x0E);
   STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
   MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

   // Rounds 28-31
   MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
   STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
   TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
   MSG0 = _mm_add_epi32(MSG0, TMP);
   MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
   MSG = _mm_shuffle_epi32(MSG, 0x0E);
   STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
   MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

   // Rounds 32-35
   MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
   STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
   TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
   MSG1 = _mm_add_epi32(MSG1, TMP);
   MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
   MSG = _mm_shuffle_epi32(MSG, 0x0E);
   STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
   MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

   // Rounds 36-39
   MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
   STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
   TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
   MSG2 = _mm_add_epi32(MSG2, TMP);
   MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
   MSG = _mm_shuffle_epi32(MSG, 0x0E);
   STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
   MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

   // Rounds 40-43
   MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
   STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
   TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
   MSG3 = _mm_add_epi32(MSG3, TMP);
   MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
   MSG = _mm_shuffle_epi32(MSG, 0x0E);
   STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
   MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

   // Rounds 44-47
   MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
   STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
   TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
   MSG0 = _mm_add_epi32(MSG0, TMP);
   MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
   MSG = _mm_shuffle_epi32(MSG, 0x0E);
   STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
   MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

   // Rounds 48-51
   MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
   STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
   TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
   MSG1 = _mm_add_epi32(MSG1, TMP);
   MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
   MSG = _mm_shuffle_epi32(MSG, 0x0E);
   STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
   MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

   // Rounds 52-55
   MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
   STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
   TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
   MSG2 = _mm_add_epi32(MSG2, TMP);
   MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
   MSG = _mm_shuffle_epi32(MSG, 0x0E);
   STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

   // Rounds 56-59
   MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
   STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
   TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
   MSG3 = _mm_add_epi32(MSG3, TMP);
   MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
   MSG = _mm_shuffle_epi32(MSG, 0x0E);
   STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

   // Rounds 60-63
   MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
   STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
   MSG = _mm_shuffle_epi32(MSG, 0x0E);
   STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

   // Combine state 
   STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
   STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

   TMP = _mm_shuffle_epi32(STATE0, 0x1B);       // FEBA
   STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);    // DCHG
   STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0); // DCBA
   STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);    // ABEF

   // Save state
   _mm_storeu_si128((__m128i*) &state_[0], STATE0);
   _mm_storeu_si128((__m128i*) &state_[4], STATE1);
}
*/