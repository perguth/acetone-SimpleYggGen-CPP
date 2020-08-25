// Source: https://github.com/jedisct1/libsodium/tree/1.0.18
// Source: https://github.com/openssl/openssl/blob/OpenSSL_1_1_1g/crypto/ec/asm/x25519-x86_64.pl

#include "x25519.h"

#include <string.h> // memcpy

typedef unsigned __int128 uint128_t;

base_powers g_base_powers;

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

#define REDUCE_ASM                                            \
	"movq   $0x7ffffffffffff,%%rbp \n"                        \
                                                              \
	"movq   %%r10,%%rdx \n"                                   \
	"shrq   $51,%%r10 \n"                                     \
	"shlq   $13,%%r11 \n"                                     \
	"andq   %%rbp,%%rdx \n"      /* %%rdx = g2 = h2 & mask */ \
	"orq    %%r10,%%r11 \n"      /* h2>>51 */                 \
	"addq   %%r11,%%r12 \n"                                   \
	"adcq   $0,%%r13 \n"         /* h3 += h2>>51 */           \
                                                              \
	"movq   %%rbx,%%rax \n"                                   \
	"shrq   $51,%%rbx \n"                                     \
	"shlq   $13,%%rcx \n"                                     \
	"andq   %%rbp,%%rax \n"      /* %%rax = g0 = h0 & mask */ \
	"orq    %%rbx,%%rcx \n"      /* h0>>51 */                 \
	"addq   %%rcx,%%r8 \n"       /* h1 += h0>>51 */           \
	"adcq   $0,%%r9 \n"                                       \
                                                              \
	"movq   %%r12,%%rbx \n"                                   \
	"shrq   $51,%%r12 \n"                                     \
	"shlq   $13,%%r13 \n"                                     \
	"andq   %%rbp,%%rbx \n"      /* %%rbx = g3 = h3 & mask */ \
	"orq    %%r12,%%r13 \n"      /* h3>>51 */                 \
	"addq   %%r13,%%r14 \n"      /* h4 += h3>>51 */           \
	"adcq   $0,%%r15 \n"                                      \
                                                              \
	"movq   %%r8,%%rcx \n"                                    \
	"shrq   $51,%%r8 \n"                                      \
	"shlq   $13,%%r9 \n"                                      \
	"andq   %%rbp,%%rcx \n"      /* %%rcx = g1 = h1 & mask */ \
	"orq    %%r8,%%r9 \n"                                     \
	"addq   %%r9,%%rdx \n"       /* g2 += h1>>51 */           \
                                                              \
	"movq   %%r14,%%r10 \n"                                   \
	"shrq   $51,%%r14 \n"                                     \
	"shlq   $13,%%r15 \n"                                     \
	"andq   %%rbp,%%r10 \n"      /* %%r10 = g4 = h0 & mask */ \
	"orq    %%r14,%%r15 \n"      /* h0>>51 */                 \
                                                              \
	"leaq   (%%r15,%%r15,8),%%r14 \n"                         \
	"leaq   (%%r15,%%r14,2),%%r15 \n"                         \
	"addq   %%r15,%%rax \n"      /* g0 += (h0>>51)*19 */      \
                                                              \
	"movq   %%rdx,%%r8 \n"                                    \
	"andq   %%rbp,%%rdx \n"      /* g2 &= mask */             \
	"shrq   $51,%%r8 \n"                                      \
	"addq   %%r8,%%rbx \n"       /* g3 += g2>>51 */           \
                                                              \
	"movq   %%rax,%%r9 \n"                                    \
	"andq   %%rbp,%%rax \n"      /* g0 &= mask */             \
	"shrq   $51,%%r9 \n"                                      \
	"addq   %%r9,%%rcx \n"       /* g1 += g0>>51 */           \
                                                              \
	"movq   %%rax,8*0(%%rdi) \n" /* save the result */        \
	"movq   %%rcx,8*1(%%rdi) \n"                              \
	"movq   %%rdx,8*2(%%rdi) \n"                              \
	"movq   %%rbx,8*3(%%rdi) \n"                              \
	"movq   %%r10,8*4(%%rdi) \n"

/*
h = f * g
Can overlap h with f or g.
*/

static void
fe25519_mul(fe25519 h, const fe25519 f, const fe25519 g)
{
	uint64_t t1, t2, t3, t4;
	__asm__ (
		"pushq  %%r15 \n"
		"pushq  %%r14 \n"
		"pushq  %%r13 \n"

		"movq   %4,%%rdi \n"
		"movq   %5,%%rsi \n"
		"movq   %6,%%rdx \n"

		"movq   8*0(%%rsi),%%rax \n"      // f[0]
		"movq   8*0(%%rdx),%%r11 \n"      // load g[0-4]
		"movq   8*1(%%rdx),%%r12 \n"
		"movq   8*2(%%rdx),%%r13 \n"
		"movq   8*3(%%rdx),%%rbp \n"
		"movq   8*4(%%rdx),%%r14 \n"

		"movq   %%rdi,%3 \n"              // offload 1st argument
		"movq   %%rax,%%rdi \n"
		"mulq   %%r11 \n"                 // f[0]*g[0]
		"movq   %%r11,%0 \n"              // offload g[0]
		"movq   %%rax,%%rbx \n"           // %%rbx:%%rcx = h0
		"movq   %%rdi,%%rax \n"
		"movq   %%rdx,%%rcx \n"
		"mulq   %%r12 \n"                 // f[0]*g[1]
		"movq   %%r12,%1 \n"              // offload g[1]
		"movq   %%rax,%%r8 \n"            // %%r8:%%r9 = h1
		"movq   %%rdi,%%rax \n"
		"leaq   (%%r14,%%r14,8),%%r15 \n"
		"movq   %%rdx,%%r9 \n"
		"mulq   %%r13 \n"                 // f[0]*g[2]
		"movq   %%r13,%2 \n"              // offload g[2]
		"movq   %%rax,%%r10 \n"           // %%r10:%%r11 = h2
		"movq   %%rdi,%%rax \n"
		"leaq   (%%r14,%%r15,2),%%rdi \n" // g[4]*19
		"movq   %%rdx,%%r11 \n"
		"mulq   %%rbp \n"                 // f[0]*g[3]
		"movq   %%rax,%%r12 \n"           // %%r12:%%r13 = h3
		"movq   8*0(%%rsi),%%rax \n"      // f[0]
		"movq   %%rdx,%%r13 \n"
		"mulq   %%r14 \n"                 // f[0]*g[4]
		"movq   %%rax,%%r14 \n"           // %%r14:%%r15 = h4
		"movq   8*1(%%rsi),%%rax \n"      // f[1]
		"movq   %%rdx,%%r15 \n"

		"mulq   %%rdi \n"                 // f[1]*g[4]*19
		"addq   %%rax,%%rbx \n"
		"movq   8*2(%%rsi),%%rax \n"      // f[2]
		"adcq   %%rdx,%%rcx \n"
		"mulq   %%rdi \n"                 // f[2]*g[4]*19
		"addq   %%rax,%%r8 \n"
		"movq   8*3(%%rsi),%%rax \n"      // f[3]
		"adcq   %%rdx,%%r9 \n"
		"mulq   %%rdi \n"                 // f[3]*g[4]*19
		"addq   %%rax,%%r10 \n"
		"movq   8*4(%%rsi),%%rax \n"      // f[4]
		"adcq   %%rdx,%%r11 \n"
		"mulq   %%rdi \n"                 // f[4]*g[4]*19
		"imulq  $19,%%rbp,%%rdi \n"       // g[3]*19
		"addq   %%rax,%%r12 \n"
		"movq   8*1(%%rsi),%%rax \n"      // f[1]
		"adcq   %%rdx,%%r13 \n"
		"mulq   %%rbp \n"                 // f[1]*g[3]
		"movq   %2,%%rbp \n"              // g[2]
		"addq   %%rax,%%r14 \n"
		"movq   8*2(%%rsi),%%rax \n"      // f[2]
		"adcq   %%rdx,%%r15 \n"

		"mulq   %%rdi \n"                 // f[2]*g[3]*19
		"addq   %%rax,%%rbx \n"
		"movq   8*3(%%rsi),%%rax \n"      // f[3]
		"adcq   %%rdx,%%rcx \n"
		"mulq   %%rdi \n"                 // f[3]*g[3]*19
		"addq   %%rax,%%r8 \n"
		"movq   8*4(%%rsi),%%rax \n"      // f[4]
		"adcq   %%rdx,%%r9 \n"
		"mulq   %%rdi \n"                 // f[4]*g[3]*19
		"imulq  $19,%%rbp,%%rdi \n"       // g[2]*19
		"addq   %%rax,%%r10 \n"
		"movq   8*1(%%rsi),%%rax \n"      // f[1]
		"adcq   %%rdx,%%r11 \n"
		"mulq   %%rbp \n"                 // f[1]*g[2]
		"addq   %%rax,%%r12 \n"
		"movq   8*2(%%rsi),%%rax \n"      // f[2]
		"adcq   %%rdx,%%r13 \n"
		"mulq   %%rbp \n"                 // f[2]*g[2]
		"movq   %1,%%rbp \n"              // g[1]
		"addq   %%rax,%%r14 \n"
		"movq   8*3(%%rsi),%%rax \n"      // f[3]
		"adcq   %%rdx,%%r15 \n"

		"mulq   %%rdi \n"                 // f[3]*g[2]*19
		"addq   %%rax,%%rbx \n"
		"movq   8*4(%%rsi),%%rax \n"      // f[3]
		"adcq   %%rdx,%%rcx \n"
		"mulq   %%rdi \n"                 // f[4]*g[2]*19
		"addq   %%rax,%%r8 \n"
		"movq   8*1(%%rsi),%%rax \n"      // f[1]
		"adcq   %%rdx,%%r9 \n"
		"mulq   %%rbp \n"                 // f[1]*g[1]
		"imulq  $19,%%rbp,%%rdi \n"
		"addq   %%rax,%%r10 \n"
		"movq   8*2(%%rsi),%%rax \n"      // f[2]
		"adcq   %%rdx,%%r11 \n"
		"mulq   %%rbp \n"                 // f[2]*g[1]
		"addq   %%rax,%%r12 \n"
		"movq   8*3(%%rsi),%%rax \n"      // f[3]
		"adcq   %%rdx,%%r13 \n"
		"mulq   %%rbp \n"                 // f[3]*g[1]
		"movq   %0,%%rbp \n"              // g[0]
		"addq   %%rax,%%r14 \n"
		"movq   8*4(%%rsi),%%rax \n"      // f[4]
		"adcq   %%rdx,%%r15 \n"

		"mulq   %%rdi \n"                 // f[4]*g[1]*19
		"addq   %%rax,%%rbx \n"
		"movq   8*1(%%rsi),%%rax \n"      // f[1]
		"adcq   %%rdx,%%rcx \n"
		"mulq   %%rbp \n"                 // f[1]*g[0]
		"addq   %%rax,%%r8 \n"
		"movq   8*2(%%rsi),%%rax \n"      // f[2]
		"adcq   %%rdx,%%r9 \n"
		"mulq   %%rbp \n"                 // f[2]*g[0]
		"addq   %%rax,%%r10 \n"
		"movq   8*3(%%rsi),%%rax \n"      // f[3]
		"adcq   %%rdx,%%r11 \n"
		"mulq   %%rbp \n"                 // f[3]*g[0]
		"addq   %%rax,%%r12 \n"
		"movq   8*4(%%rsi),%%rax \n"      // f[4]
		"adcq   %%rdx,%%r13 \n"
		"mulq   %%rbp \n"                 // f[4]*g[0]
		"addq   %%rax,%%r14 \n"
		"adcq   %%rdx,%%r15 \n"

		"movq   %3,%%rdi \n"              // restore 1st argument

		REDUCE_ASM

		"popq   %%r13 \n"
		"popq   %%r14 \n"
		"popq   %%r15 \n"

		: "+m"(t1), "+m"(t2), "+m"(t3), "+m"(t4)
		: "r"(h), "r"(f), "r"(g)
		: "%rax", "%rbx", "%rcx", "%rdx", "%rdi", "%rsi", "%rbp",
		  "%r8", "%r9", "%r10", "%r11", "%r12", "memory"
	);
}


/*
h = f * f
Can overlap h with f.
*/

static void fe25519_sq(fe25519 h, const fe25519 f)
{
	uint64_t t1, t2, t3, t4;
	__asm__ (
		"pushq  %%r15 \n"
		"pushq  %%r14 \n"

		"movq   %4, %%rdi \n"
		"movq   %5, %%rsi \n"

		"movq   8*0(%%rsi),%%rax \n"      // g[0]
		"movq   8*2(%%rsi),%%r15 \n"      // g[2]
		"movq   8*4(%%rsi),%%rbp \n"      // g[4]

		"movq   %%rdi,%3 \n"              // offload 1st argument
		"leaq   (%%rax,%%rax),%%r14 \n"
		"mulq   %%rax \n"                 // g[0]*g[0]
		"movq   %%rax,%%rbx \n"
		"movq   8*1(%%rsi),%%rax \n"      // g[1]
		"movq   %%rdx,%%rcx \n"
		"mulq   %%r14 \n"                 // 2*g[0]*g[1]
		"movq   %%rax,%%r8 \n"
		"movq   %%r15,%%rax \n"
		"movq   %%r15,%0 \n"              // offload g[2]
		"movq   %%rdx,%%r9 \n"
		"mulq   %%r14 \n"                 // 2*g[0]*g[2]
		"movq   %%rax,%%r10 \n"
		"movq   8*3(%%rsi),%%rax \n"
		"movq   %%rdx,%%r11 \n"
		"imulq  $19,%%rbp,%%rdi \n"       // g[4]*19
		"mulq   %%r14 \n"                 // 2*g[0]*g[3]
		"movq   %%rax,%%r12 \n"
		"movq   %%rbp,%%rax \n"
		"movq   %%rdx,%%r13 \n"
		"mulq   %%r14 \n"                 // 2*g[0]*g[4]
		"movq   %%rax,%%r14 \n"
		"movq   %%rbp,%%rax \n"
		"movq   %%rdx,%%r15 \n"

		"mulq   %%rdi \n"                 // g[4]*g[4]*19
		"addq   %%rax,%%r12 \n"
		"movq   8*1(%%rsi),%%rax \n"      // g[1]
		"adcq   %%rdx,%%r13 \n"

		"movq   8*3(%%rsi),%%rsi \n"      // g[3]
		"leaq   (%%rax,%%rax),%%rbp \n"
		"mulq   %%rax \n"                 // g[1]*g[1]
		"addq   %%rax,%%r10 \n"
		"movq   %0,%%rax \n"              // g[2]
		"adcq   %%rdx,%%r11 \n"
		"mulq   %%rbp \n"                 // 2*g[1]*g[2]
		"addq   %%rax,%%r12 \n"
		"movq   %%rbp,%%rax \n"
		"adcq   %%rdx,%%r13 \n"
		"mulq   %%rsi \n"                 // 2*g[1]*g[3]
		"addq   %%rax,%%r14 \n"
		"movq   %%rbp,%%rax \n"
		"adcq   %%rdx,%%r15 \n"
		"imulq  $19,%%rsi,%%rbp \n"       // g[3]*19
		"mulq   %%rdi \n"                 // 2*g[1]*g[4]*19
		"addq   %%rax,%%rbx \n"
		"leaq   (%%rsi,%%rsi),%%rax \n"
		"adcq   %%rdx,%%rcx \n"

		"mulq   %%rdi \n"                 // 2*g[3]*g[4]*19
		"addq   %%rax,%%r10 \n"
		"movq   %%rsi,%%rax \n"
		"adcq   %%rdx,%%r11 \n"
		"mulq   %%rbp \n"                 // g[3]*g[3]*19
		"addq   %%rax,%%r8 \n"
		"movq   %0,%%rax \n"              // g[2]
		"adcq   %%rdx,%%r9 \n"

		"leaq   (%%rax,%%rax),%%rsi \n"
		"mulq   %%rax \n"                 // g[2]*g[2]
		"addq   %%rax,%%r14 \n"
		"movq   %%rbp,%%rax \n"
		"adcq   %%rdx,%%r15 \n"
		"mulq   %%rsi \n"                 // 2*g[2]*g[3]*19
		"addq   %%rax,%%rbx \n"
		"movq   %%rsi,%%rax \n"
		"adcq   %%rdx,%%rcx \n"
		"mulq   %%rdi \n"                 // 2*g[2]*g[4]*19
		"addq   %%rax,%%r8 \n"
		"adcq   %%rdx,%%r9 \n"

		"movq   %3,%%rdi \n"              // restore 1st argument

		REDUCE_ASM

		"popq   %%r14 \n"
		"popq   %%r15 \n"

		: "+m"(t1), "+m"(t2), "+m"(t3), "+m"(t4)
		: "r"(h), "r"(f)
		: "%rax", "%rbx", "%rcx", "%rdx", "%rdi", "%rsi", "%rbp",
		  "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "memory"
	);
}

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

static void ge25519_add(ge25519* r, const ge25519* p, const ge25519* q)
{
	static const fe25519 d2 = {
		0x69b9426b2f159, 0x35050762add7a,
		0x3cf44c0038052, 0x6738cc7407977, 0x2406d9dc56dff };

	fe25519 a, b, c, d, t, e, f, g, h;

	fe25519_sub(a, p->Y, p->X);
	fe25519_sub(t, q->Y, q->X);
	fe25519_mul(a, a, t);
	fe25519_add(b, p->X, p->Y);
	fe25519_add(t, q->X, q->Y);
	fe25519_mul(b, b, t);
	fe25519_mul(c, p->T, q->T);
	fe25519_mul(c, c, d2);
	fe25519_mul(d, p->Z, q->Z);
	fe25519_add(d, d, d);
	fe25519_sub(e, b, a);
	fe25519_sub(f, d, c);
	fe25519_add(g, d, c);
	fe25519_add(h, b, a);

	fe25519_mul(r->X, e, f);
	fe25519_mul(r->Y, h, g);
	fe25519_mul(r->Z, g, f);
	fe25519_mul(r->T, e, h);
}

void keys_block::calculate_public_keys(const uint8_t random_bytes[KEYSIZE])
{
	state.clear();
	for (int i = 0; i < 256; i++)
		key_bits[i] = (random_bytes[i / 8] >> (i & 7)) & 1;
	key_bits[0] = 0;
	key_bits[1] = 0;
	key_bits[2] = 0;
	key_bits[255] = 0;
	key_bits[254] = 1;

	for (int i = 0; i < points.size(); i++)
	{
		ge25519& h = points[i];
		if (state.size() == 0)
			h = g_base_powers.get(254);
		else
			h = state.back();

		for (int j = 253 - state.size(); j >= 3; j--)
		{
			if (key_bits[j])
				ge25519_add(&h, &h, &g_base_powers.get(j));
			state.push_back(h);
		}

		fe25519_add(h.T, h.Z, h.Y);
		fe25519_sub(temp_z[i], h.Z, h.Y);

		for (int j = 3; ; j++)
		{
			key_bits[j]--;
			state.pop_back();
			if (key_bits[j] == 0)
				break;
			else
				key_bits[j] = 1;
		}
	}

	// Multiple inversion
	memcpy(points[0].Y, temp_z[0], sizeof(fe25519));
	for (int i = 1; i < points.size(); i++)
		fe25519_mul(points[i].Y, temp_z[i], points[i - 1].Y);
	fe25519_invert(points.back().Z, points.back().Y);
	for (int i = points.size() - 1; i >= 1; i--)
	{
		fe25519_mul(points[i - 1].Z, points[i].Z, temp_z[i]);
		fe25519_mul(temp_z[i], points[i].Z, points[i - 1].Y);
	}
	memcpy(temp_z[0], points[0].Z, sizeof(fe25519));

	for (int i = 0; i < points.size(); i++)
		fe25519_mul(points[i].X, points[i].T, temp_z[i]);
}

void keys_block::get_public_key(key25519 public_key, int index) const
{
	fe25519_tobytes(public_key, points[index].X);
}

void keys_block::get_private_key(key25519 private_key, int index) const
{
	for (int i = 0; i < 32; i++)
		private_key[i] = 0;
	for (int i = 0; i < 256; i++)
		private_key[i / 8] |= key_bits[i] << (i & 7);

	key25519 key_delta = { 0 };
	*(uint64_t*)key_delta = (points.size() - index) * 8;
	int carry = 0;
	for (int i = 0; i < 32; i++)
	{
		int temp = private_key[i] + key_delta[i] + carry;
		private_key[i] = (uint8_t)temp;
		carry = temp > 0xFF;
	}
}

keys_block::keys_block(int size)
	: points(size), temp_z(size)
{

}

base_powers::base_powers()
{
	ge25519 q = {
		{ 0x62d608f25d51a, 0x412a4b4f6592a,
		  0x75b7171a4b31d, 0x1ff60527118fe, 0x216936d3cd6e5 },
		{ 0x6666666666658, 0x4cccccccccccc,
		  0x1999999999999, 0x3333333333333, 0x6666666666666 },
		{ 1, 0, 0, 0, 0 },
		{ 0x68ab3a5b7dda3, 0x00eea2a5eadbb, 0x2af8df483c27e,
		  0x332b375274732, 0x67875f0fd78b7 }
	};

	for (int i = 0; i < 255; i++)
	{
		data[i] = q;
		ge25519_add(&q, &q, &q);
	}
}

const ge25519& base_powers::get(int index)
{
	return data[index];
}