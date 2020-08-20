#include <string.h> // memcpy
#include <stdint.h>

typedef unsigned __int128 uint128_t;

typedef uint64_t fe25519[5];

typedef struct {
	fe25519 X;
	fe25519 Y;
	fe25519 Z;
} ge25519_p2;

typedef struct {
	fe25519 X;
	fe25519 Y;
	fe25519 Z;
	fe25519 T;
} ge25519_p3;

typedef struct {
	fe25519 X;
	fe25519 Y;
	fe25519 Z;
	fe25519 T;
} ge25519_p1p1;

typedef struct {
	fe25519 yplusx;
	fe25519 yminusx;
	fe25519 xy2d;
} ge25519_precomp;

/*
h = 0
*/

static inline void
fe25519_0(fe25519 h)
{
	memset(&h[0], 0, 5 * sizeof h[0]);
}

/*
h = 1
*/

static inline void
fe25519_1(fe25519 h)
{
	h[0] = 1;
	memset(&h[1], 0, 4 * sizeof h[0]);
}

/*
h = f + g
Can overlap h with f or g.
*/

static inline void
fe25519_add(fe25519 h, const fe25519 f, const fe25519 g)
{
	uint64_t h0 = f[0] + g[0];
	uint64_t h1 = f[1] + g[1];
	uint64_t h2 = f[2] + g[2];
	uint64_t h3 = f[3] + g[3];
	uint64_t h4 = f[4] + g[4];

	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;
}

/*
h = f - g
*/

static void
fe25519_sub(fe25519 h, const fe25519 f, const fe25519 g)
{
	const uint64_t mask = 0x7ffffffffffffULL;
	uint64_t h0, h1, h2, h3, h4;

	h0 = g[0];
	h1 = g[1];
	h2 = g[2];
	h3 = g[3];
	h4 = g[4];

	h1 += h0 >> 51;
	h0 &= mask;
	h2 += h1 >> 51;
	h1 &= mask;
	h3 += h2 >> 51;
	h2 &= mask;
	h4 += h3 >> 51;
	h3 &= mask;
	h0 += 19ULL * (h4 >> 51);
	h4 &= mask;

	h0 = (f[0] + 0xfffffffffffdaULL) - h0;
	h1 = (f[1] + 0xffffffffffffeULL) - h1;
	h2 = (f[2] + 0xffffffffffffeULL) - h2;
	h3 = (f[3] + 0xffffffffffffeULL) - h3;
	h4 = (f[4] + 0xffffffffffffeULL) - h4;

	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;
}

/*
h = -f
*/

static inline void
fe25519_neg(fe25519 h, const fe25519 f)
{
	fe25519 zero;

	fe25519_0(zero);
	fe25519_sub(h, zero, f);
}

/*
h = f * g
Can overlap h with f or g.
*/

extern "C" void x25519_fe51_mul(fe25519 h, const fe25519 f, const fe25519 g);
#define fe25519_mul x25519_fe51_mul

/*
static void
fe25519_mul(fe25519 h, const fe25519 f, const fe25519 g)
{
	const uint64_t mask = 0x7ffffffffffffULL;
	uint128_t r0, r1, r2, r3, r4, carry;
	uint64_t  f0, f1, f2, f3, f4;
	uint64_t  f1_19, f2_19, f3_19, f4_19;
	uint64_t  g0, g1, g2, g3, g4;
	uint64_t  r00, r01, r02, r03, r04;

	f0 = f[0];
	f1 = f[1];
	f2 = f[2];
	f3 = f[3];
	f4 = f[4];

	g0 = g[0];
	g1 = g[1];
	g2 = g[2];
	g3 = g[3];
	g4 = g[4];

	f1_19 = 19ULL * f1;
	f2_19 = 19ULL * f2;
	f3_19 = 19ULL * f3;
	f4_19 = 19ULL * f4;

	r0 = ((uint128_t)f0) * ((uint128_t)g0);
	r0 += ((uint128_t)f1_19) * ((uint128_t)g4);
	r0 += ((uint128_t)f2_19) * ((uint128_t)g3);
	r0 += ((uint128_t)f3_19) * ((uint128_t)g2);
	r0 += ((uint128_t)f4_19) * ((uint128_t)g1);

	r1 = ((uint128_t)f0) * ((uint128_t)g1);
	r1 += ((uint128_t)f1) * ((uint128_t)g0);
	r1 += ((uint128_t)f2_19) * ((uint128_t)g4);
	r1 += ((uint128_t)f3_19) * ((uint128_t)g3);
	r1 += ((uint128_t)f4_19) * ((uint128_t)g2);

	r2 = ((uint128_t)f0) * ((uint128_t)g2);
	r2 += ((uint128_t)f1) * ((uint128_t)g1);
	r2 += ((uint128_t)f2) * ((uint128_t)g0);
	r2 += ((uint128_t)f3_19) * ((uint128_t)g4);
	r2 += ((uint128_t)f4_19) * ((uint128_t)g3);

	r3 = ((uint128_t)f0) * ((uint128_t)g3);
	r3 += ((uint128_t)f1) * ((uint128_t)g2);
	r3 += ((uint128_t)f2) * ((uint128_t)g1);
	r3 += ((uint128_t)f3) * ((uint128_t)g0);
	r3 += ((uint128_t)f4_19) * ((uint128_t)g4);

	r4 = ((uint128_t)f0) * ((uint128_t)g4);
	r4 += ((uint128_t)f1) * ((uint128_t)g3);
	r4 += ((uint128_t)f2) * ((uint128_t)g2);
	r4 += ((uint128_t)f3) * ((uint128_t)g1);
	r4 += ((uint128_t)f4) * ((uint128_t)g0);

	r00 = ((uint64_t)r0) & mask;
	carry = r0 >> 51;
	r1 += carry;
	r01 = ((uint64_t)r1) & mask;
	carry = r1 >> 51;
	r2 += carry;
	r02 = ((uint64_t)r2) & mask;
	carry = r2 >> 51;
	r3 += carry;
	r03 = ((uint64_t)r3) & mask;
	carry = r3 >> 51;
	r4 += carry;
	r04 = ((uint64_t)r4) & mask;
	carry = r4 >> 51;
	r00 += 19ULL * (uint64_t)carry;
	carry = r00 >> 51;
	r00 &= mask;
	r01 += (uint64_t)carry;
	carry = r01 >> 51;
	r01 &= mask;
	r02 += (uint64_t)carry;

	h[0] = r00;
	h[1] = r01;
	h[2] = r02;
	h[3] = r03;
	h[4] = r04;
}
*/

/*
h = f * f
Can overlap h with f.
*/

extern "C" void x25519_fe51_sqr(fe25519 h, const fe25519 f);
#define fe25519_sq x25519_fe51_sqr

/*
static void
fe25519_sq(fe25519 h, const fe25519 f)
{
	const uint64_t mask = 0x7ffffffffffffULL;
	uint128_t r0, r1, r2, r3, r4, carry;
	uint64_t  f0, f1, f2, f3, f4;
	uint64_t  f0_2, f1_2, f1_38, f2_38, f3_38, f3_19, f4_19;
	uint64_t  r00, r01, r02, r03, r04;

	f0 = f[0];
	f1 = f[1];
	f2 = f[2];
	f3 = f[3];
	f4 = f[4];

	f0_2 = f0 << 1;
	f1_2 = f1 << 1;

	f1_38 = 38ULL * f1;
	f2_38 = 38ULL * f2;
	f3_38 = 38ULL * f3;

	f3_19 = 19ULL * f3;
	f4_19 = 19ULL * f4;

	r0 = ((uint128_t)f0) * ((uint128_t)f0);
	r0 += ((uint128_t)f1_38) * ((uint128_t)f4);
	r0 += ((uint128_t)f2_38) * ((uint128_t)f3);

	r1 = ((uint128_t)f0_2) * ((uint128_t)f1);
	r1 += ((uint128_t)f2_38) * ((uint128_t)f4);
	r1 += ((uint128_t)f3_19) * ((uint128_t)f3);

	r2 = ((uint128_t)f0_2) * ((uint128_t)f2);
	r2 += ((uint128_t)f1) * ((uint128_t)f1);
	r2 += ((uint128_t)f3_38) * ((uint128_t)f4);

	r3 = ((uint128_t)f0_2) * ((uint128_t)f3);
	r3 += ((uint128_t)f1_2) * ((uint128_t)f2);
	r3 += ((uint128_t)f4_19) * ((uint128_t)f4);

	r4 = ((uint128_t)f0_2) * ((uint128_t)f4);
	r4 += ((uint128_t)f1_2) * ((uint128_t)f3);
	r4 += ((uint128_t)f2) * ((uint128_t)f2);

	r00 = ((uint64_t)r0) & mask;
	carry = r0 >> 51;
	r1 += carry;
	r01 = ((uint64_t)r1) & mask;
	carry = r1 >> 51;
	r2 += carry;
	r02 = ((uint64_t)r2) & mask;
	carry = r2 >> 51;
	r3 += carry;
	r03 = ((uint64_t)r3) & mask;
	carry = r3 >> 51;
	r4 += carry;
	r04 = ((uint64_t)r4) & mask;
	carry = r4 >> 51;
	r00 += 19ULL * (uint64_t)carry;
	carry = r00 >> 51;
	r00 &= mask;
	r01 += (uint64_t)carry;
	carry = r01 >> 51;
	r01 &= mask;
	r02 += (uint64_t)carry;

	h[0] = r00;
	h[1] = r01;
	h[2] = r02;
	h[3] = r03;
	h[4] = r04;
}
*/

static void
fe25519_invert(fe25519 out, const fe25519 z)
{
	fe25519 t0;
	fe25519 t1;
	fe25519 t2;
	fe25519 t3;
	int     i;

	fe25519_sq(t0, z);
	fe25519_sq(t1, t0);
	fe25519_sq(t1, t1);
	fe25519_mul(t1, z, t1);
	fe25519_mul(t0, t0, t1);
	fe25519_sq(t2, t0);
	fe25519_mul(t1, t1, t2);
	fe25519_sq(t2, t1);
	for (i = 1; i < 5; ++i) {
		fe25519_sq(t2, t2);
	}
	fe25519_mul(t1, t2, t1);
	fe25519_sq(t2, t1);
	for (i = 1; i < 10; ++i) {
		fe25519_sq(t2, t2);
	}
	fe25519_mul(t2, t2, t1);
	fe25519_sq(t3, t2);
	for (i = 1; i < 20; ++i) {
		fe25519_sq(t3, t3);
	}
	fe25519_mul(t2, t3, t2);
	for (i = 1; i < 11; ++i) {
		fe25519_sq(t2, t2);
	}
	fe25519_mul(t1, t2, t1);
	fe25519_sq(t2, t1);
	for (i = 1; i < 50; ++i) {
		fe25519_sq(t2, t2);
	}
	fe25519_mul(t2, t2, t1);
	fe25519_sq(t3, t2);
	for (i = 1; i < 100; ++i) {
		fe25519_sq(t3, t3);
	}
	fe25519_mul(t2, t3, t2);
	for (i = 1; i < 51; ++i) {
		fe25519_sq(t2, t2);
	}
	fe25519_mul(t1, t2, t1);
	for (i = 1; i < 6; ++i) {
		fe25519_sq(t1, t1);
	}
	fe25519_mul(out, t1, t0);
}

static void
fe25519_reduce(fe25519 h, const fe25519 f)
{
	const uint64_t mask = 0x7ffffffffffffULL;
	uint128_t t[5];

	t[0] = f[0];
	t[1] = f[1];
	t[2] = f[2];
	t[3] = f[3];
	t[4] = f[4];

	t[1] += t[0] >> 51;
	t[0] &= mask;
	t[2] += t[1] >> 51;
	t[1] &= mask;
	t[3] += t[2] >> 51;
	t[2] &= mask;
	t[4] += t[3] >> 51;
	t[3] &= mask;
	t[0] += 19 * (t[4] >> 51);
	t[4] &= mask;

	t[1] += t[0] >> 51;
	t[0] &= mask;
	t[2] += t[1] >> 51;
	t[1] &= mask;
	t[3] += t[2] >> 51;
	t[2] &= mask;
	t[4] += t[3] >> 51;
	t[3] &= mask;
	t[0] += 19 * (t[4] >> 51);
	t[4] &= mask;

	/* now t is between 0 and 2^255-1, properly carried. */
	/* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */

	t[0] += 19ULL;

	t[1] += t[0] >> 51;
	t[0] &= mask;
	t[2] += t[1] >> 51;
	t[1] &= mask;
	t[3] += t[2] >> 51;
	t[2] &= mask;
	t[4] += t[3] >> 51;
	t[3] &= mask;
	t[0] += 19ULL * (t[4] >> 51);
	t[4] &= mask;

	/* now between 19 and 2^255-1 in both cases, and offset by 19. */

	t[0] += 0x8000000000000 - 19ULL;
	t[1] += 0x8000000000000 - 1ULL;
	t[2] += 0x8000000000000 - 1ULL;
	t[3] += 0x8000000000000 - 1ULL;
	t[4] += 0x8000000000000 - 1ULL;

	/* now between 2^255 and 2^256-20, and offset by 2^255. */

	t[1] += t[0] >> 51;
	t[0] &= mask;
	t[2] += t[1] >> 51;
	t[1] &= mask;
	t[3] += t[2] >> 51;
	t[2] &= mask;
	t[4] += t[3] >> 51;
	t[3] &= mask;
	t[4] &= mask;

	h[0] = t[0];
	h[1] = t[1];
	h[2] = t[2];
	h[3] = t[3];
	h[4] = t[4];
}

/*
h = 2 * f * f
Can overlap h with f.
*/

static void
fe25519_sq2(fe25519 h, const fe25519 f)
{
	const uint64_t mask = 0x7ffffffffffffULL;
	uint128_t r0, r1, r2, r3, r4, carry;
	uint64_t  f0, f1, f2, f3, f4;
	uint64_t  f0_2, f1_2, f1_38, f2_38, f3_38, f3_19, f4_19;
	uint64_t  r00, r01, r02, r03, r04;

	f0 = f[0];
	f1 = f[1];
	f2 = f[2];
	f3 = f[3];
	f4 = f[4];

	f0_2 = f0 << 1;
	f1_2 = f1 << 1;

	f1_38 = 38ULL * f1;
	f2_38 = 38ULL * f2;
	f3_38 = 38ULL * f3;

	f3_19 = 19ULL * f3;
	f4_19 = 19ULL * f4;

	r0 = ((uint128_t)f0) * ((uint128_t)f0);
	r0 += ((uint128_t)f1_38) * ((uint128_t)f4);
	r0 += ((uint128_t)f2_38) * ((uint128_t)f3);

	r1 = ((uint128_t)f0_2) * ((uint128_t)f1);
	r1 += ((uint128_t)f2_38) * ((uint128_t)f4);
	r1 += ((uint128_t)f3_19) * ((uint128_t)f3);

	r2 = ((uint128_t)f0_2) * ((uint128_t)f2);
	r2 += ((uint128_t)f1) * ((uint128_t)f1);
	r2 += ((uint128_t)f3_38) * ((uint128_t)f4);

	r3 = ((uint128_t)f0_2) * ((uint128_t)f3);
	r3 += ((uint128_t)f1_2) * ((uint128_t)f2);
	r3 += ((uint128_t)f4_19) * ((uint128_t)f4);

	r4 = ((uint128_t)f0_2) * ((uint128_t)f4);
	r4 += ((uint128_t)f1_2) * ((uint128_t)f3);
	r4 += ((uint128_t)f2) * ((uint128_t)f2);

	r0 <<= 1;
	r1 <<= 1;
	r2 <<= 1;
	r3 <<= 1;
	r4 <<= 1;

	r00 = ((uint64_t)r0) & mask;
	carry = r0 >> 51;
	r1 += carry;
	r01 = ((uint64_t)r1) & mask;
	carry = r1 >> 51;
	r2 += carry;
	r02 = ((uint64_t)r2) & mask;
	carry = r2 >> 51;
	r3 += carry;
	r03 = ((uint64_t)r3) & mask;
	carry = r3 >> 51;
	r4 += carry;
	r04 = ((uint64_t)r4) & mask;
	carry = r4 >> 51;
	r00 += 19ULL * (uint64_t)carry;
	carry = r00 >> 51;
	r00 &= mask;
	r01 += (uint64_t)carry;
	carry = r01 >> 51;
	r01 &= mask;
	r02 += (uint64_t)carry;

	h[0] = r00;
	h[1] = r01;
	h[2] = r02;
	h[3] = r03;
	h[4] = r04;
}


/*
h = f
*/

static inline void
fe25519_copy(fe25519 h, const fe25519 f)
{
	uint64_t f0 = f[0];
	uint64_t f1 = f[1];
	uint64_t f2 = f[2];
	uint64_t f3 = f[3];
	uint64_t f4 = f[4];

	h[0] = f0;
	h[1] = f1;
	h[2] = f2;
	h[3] = f3;
	h[4] = f4;
}

static void
fe25519_tobytes(unsigned char *s, const fe25519 h)
{
	fe25519  t;
	uint64_t t0, t1, t2, t3;

	fe25519_reduce(t, h);
	t0 = t[0] | (t[1] << 51);
	t1 = (t[1] >> 13) | (t[2] << 38);
	t2 = (t[2] >> 26) | (t[3] << 25);
	t3 = (t[3] >> 39) | (t[4] << 12);
	memcpy(s + 0, &t0, sizeof t0);
	memcpy(s + 8, &t1, sizeof t1);
	memcpy(s + 16, &t2, sizeof t2);
	memcpy(s + 24, &t3, sizeof t3);
}

static unsigned char
negative(signed char b)
{
	/* 18446744073709551361..18446744073709551615: yes; 0..255: no */
	uint64_t x = b;

	x >>= 63; /* 1: yes; 0: no */

	return x;
}

static unsigned char
equal(signed char b, signed char c)
{
	unsigned char ub = b;
	unsigned char uc = c;
	unsigned char x = ub ^ uc; /* 0: yes; 1..255: no */
	uint32_t      y = (uint32_t)x; /* 0: yes; 1..255: no */

	y -= 1;   /* 4294967295: yes; 0..254: no */
	y >>= 31; /* 1: yes; 0: no */

	return y;
}

static void
ge25519_p3_0(ge25519_p3 *h)
{
	fe25519_0(h->X);
	fe25519_1(h->Y);
	fe25519_1(h->Z);
	fe25519_0(h->T);
}


/*
Replace (t,u) with (u,u) if b == 1;
replace (t,u) with (t,u) if b == 0.
*
Preconditions: b in {0,1}.
*/

static void
ge25519_cmov(ge25519_precomp *t, const ge25519_precomp *u, unsigned char b)
{
	if (b)
		memcpy(t, u, sizeof *t);
}

/*
r = p
*/

static void
ge25519_p3_to_p2(ge25519_p2 *r, const ge25519_p3 *p)
{
	fe25519_copy(r->X, p->X);
	fe25519_copy(r->Y, p->Y);
	fe25519_copy(r->Z, p->Z);
}

/*
r = 2 * p
*/

static void
ge25519_p2_dbl(ge25519_p1p1 *r, const ge25519_p2 *p)
{
	fe25519 t0;

	fe25519_sq(r->X, p->X);
	fe25519_sq(r->Z, p->Y);
	fe25519_sq2(r->T, p->Z);
	fe25519_add(r->Y, p->X, p->Y);
	fe25519_sq(t0, r->Y);
	fe25519_add(r->Y, r->Z, r->X);
	fe25519_sub(r->Z, r->Z, r->X);
	fe25519_sub(r->X, t0, r->Y);
	fe25519_sub(r->T, r->T, r->Z);
}

/*
r = 2 * p
*/

static void
ge25519_p3_dbl(ge25519_p1p1 *r, const ge25519_p3 *p)
{
	ge25519_p2 q;
	ge25519_p3_to_p2(&q, p);
	ge25519_p2_dbl(r, &q);
}

static void
ge25519_precomp_0(ge25519_precomp *h)
{
	fe25519_1(h->yplusx);
	fe25519_1(h->yminusx);
	fe25519_0(h->xy2d);
}

static void
ge25519_cmov8(ge25519_precomp *t, const ge25519_precomp precomp[8], const signed char b)
{
	ge25519_precomp     minust;
	const unsigned char bnegative = negative(b);
	const unsigned char babs = b - (((-bnegative) & b) * ((signed char)1 << 1));

	ge25519_precomp_0(t);
	ge25519_cmov(t, &precomp[0], equal(babs, 1));
	ge25519_cmov(t, &precomp[1], equal(babs, 2));
	ge25519_cmov(t, &precomp[2], equal(babs, 3));
	ge25519_cmov(t, &precomp[3], equal(babs, 4));
	ge25519_cmov(t, &precomp[4], equal(babs, 5));
	ge25519_cmov(t, &precomp[5], equal(babs, 6));
	ge25519_cmov(t, &precomp[6], equal(babs, 7));
	ge25519_cmov(t, &precomp[7], equal(babs, 8));
	fe25519_copy(minust.yplusx, t->yminusx);
	fe25519_copy(minust.yminusx, t->yplusx);
	fe25519_neg(minust.xy2d, t->xy2d);
	ge25519_cmov(t, &minust, bnegative);
}

static void
ge25519_cmov8_base(ge25519_precomp *t, const int pos, const signed char b)
{
	static const ge25519_precomp base[32][8] = { /* base[i][j] = (j+1)*256^i*B */
		#include "fe_51_base.h"
	};
	ge25519_cmov8(t, base[pos], b);
}

/*
r = p + q
*/

static void
ge25519_madd(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_precomp *q)
{
	fe25519 t0;

	fe25519_add(r->X, p->Y, p->X);
	fe25519_sub(r->Y, p->Y, p->X);
	fe25519_mul(r->Z, r->X, q->yplusx);
	fe25519_mul(r->Y, r->Y, q->yminusx);
	fe25519_mul(r->T, q->xy2d, p->T);
	fe25519_add(t0, p->Z, p->Z);
	fe25519_sub(r->X, r->Z, r->Y);
	fe25519_add(r->Y, r->Z, r->Y);
	fe25519_add(r->Z, t0, r->T);
	fe25519_sub(r->T, t0, r->T);
}

/*
r = p
*/

static void
ge25519_p1p1_to_p2(ge25519_p2 *r, const ge25519_p1p1 *p)
{
	fe25519_mul(r->X, p->X, p->T);
	fe25519_mul(r->Y, p->Y, p->Z);
	fe25519_mul(r->Z, p->Z, p->T);
}

/*
r = p
*/

static void
ge25519_p1p1_to_p3(ge25519_p3 *r, const ge25519_p1p1 *p)
{
	fe25519_mul(r->X, p->X, p->T);
	fe25519_mul(r->Y, p->Y, p->Z);
	fe25519_mul(r->Z, p->Z, p->T);
	fe25519_mul(r->T, p->X, p->Y);
}

/*
h = a * B (with precomputation)
where a = a[0]+256*a[1]+...+256^31 a[31]
B is the Ed25519 base point (x,4/5) with x positive
(as bytes: 0x5866666666666666666666666666666666666666666666666666666666666666)

Preconditions:
a[31] <= 127
*/

static void
ge25519_scalarmult_base(ge25519_p3 *h, const unsigned char *a)
{
	signed char     e[64];
	signed char     carry;
	ge25519_p1p1    r;
	ge25519_p2      s;
	ge25519_precomp t;
	int             i;

	for (i = 0; i < 32; ++i) {
		e[2 * i + 0] = (a[i] >> 0) & 15;
		e[2 * i + 1] = (a[i] >> 4) & 15;
	}
	/* each e[i] is between 0 and 15 */
	/* e[63] is between 0 and 7 */

	carry = 0;
	for (i = 0; i < 63; ++i) {
		e[i] += carry;
		carry = e[i] + 8;
		carry >>= 4;
		e[i] -= carry * ((signed char)1 << 4);
	}
	e[63] += carry;
	/* each e[i] is between -8 and 8 */

	ge25519_p3_0(h);

	for (i = 1; i < 64; i += 2) {
		ge25519_cmov8_base(&t, i / 2, e[i]);
		ge25519_madd(&r, h, &t);
		ge25519_p1p1_to_p3(h, &r);
	}

	ge25519_p3_dbl(&r, h);
	ge25519_p1p1_to_p2(&s, &r);
	ge25519_p2_dbl(&r, &s);
	ge25519_p1p1_to_p2(&s, &r);
	ge25519_p2_dbl(&r, &s);
	ge25519_p1p1_to_p2(&s, &r);
	ge25519_p2_dbl(&r, &s);
	ge25519_p1p1_to_p3(h, &r);

	for (i = 0; i < 64; i += 2) {
		ge25519_cmov8_base(&t, i / 2, e[i]);
		ge25519_madd(&r, h, &t);
		ge25519_p1p1_to_p3(h, &r);
	}
}

static void
edwards_to_montgomery(fe25519 montgomeryX, const fe25519 edwardsY, const fe25519 edwardsZ)
{
	fe25519 tempX;
	fe25519 tempZ;

	fe25519_add(tempX, edwardsZ, edwardsY);
	fe25519_sub(tempZ, edwardsZ, edwardsY);
	fe25519_invert(tempZ, tempZ);
	fe25519_mul(montgomeryX, tempX, tempZ);
}

int
crypto_scalarmult_curve25519_base_internal(
	unsigned char *q, const unsigned char *n)
{
	unsigned char *t = q;
	ge25519_p3     A;
	fe25519        pk;
	unsigned int   i;

	for (i = 0; i < 32; i++) {
		t[i] = n[i];
	}
	t[0] &= 248;
	t[31] &= 127;
	t[31] |= 64;
	ge25519_scalarmult_base(&A, t);
	edwards_to_montgomery(pk, A.Y, A.Z);
	fe25519_tobytes(q, pk);

	return 0;
}