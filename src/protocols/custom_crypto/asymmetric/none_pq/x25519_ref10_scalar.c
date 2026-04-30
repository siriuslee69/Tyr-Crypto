#include <stdint.h>
#include <string.h>

typedef uint64_t fe25519[5];
typedef unsigned __int128 u128;

static uint64_t
load64_le(const unsigned char *src)
{
    uint64_t w = (uint64_t) src[0];
    w |= (uint64_t) src[1] << 8;
    w |= (uint64_t) src[2] << 16;
    w |= (uint64_t) src[3] << 24;
    w |= (uint64_t) src[4] << 32;
    w |= (uint64_t) src[5] << 40;
    w |= (uint64_t) src[6] << 48;
    w |= (uint64_t) src[7] << 56;
    return w;
}

static void
store64_le(unsigned char *dst, uint64_t w)
{
    dst[0] = (unsigned char) w; w >>= 8;
    dst[1] = (unsigned char) w; w >>= 8;
    dst[2] = (unsigned char) w; w >>= 8;
    dst[3] = (unsigned char) w; w >>= 8;
    dst[4] = (unsigned char) w; w >>= 8;
    dst[5] = (unsigned char) w; w >>= 8;
    dst[6] = (unsigned char) w; w >>= 8;
    dst[7] = (unsigned char) w;
}

static void
secure_memzero(void *p, size_t len)
{
    volatile unsigned char *b = (volatile unsigned char *) p;
    size_t i;

    for (i = 0; i < len; i++) {
        b[i] = 0;
    }
}

static void
fe25519_0(fe25519 h)
{
    memset(&h[0], 0, 5 * sizeof h[0]);
}

static void
fe25519_1(fe25519 h)
{
    h[0] = 1;
    memset(&h[1], 0, 4 * sizeof h[0]);
}

static void
fe25519_add(fe25519 h, const fe25519 f, const fe25519 g)
{
    h[0] = f[0] + g[0];
    h[1] = f[1] + g[1];
    h[2] = f[2] + g[2];
    h[3] = f[3] + g[3];
    h[4] = f[4] + g[4];
}

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

    h[0] = (f[0] + 0xfffffffffffdaULL) - h0;
    h[1] = (f[1] + 0xffffffffffffeULL) - h1;
    h[2] = (f[2] + 0xffffffffffffeULL) - h2;
    h[3] = (f[3] + 0xffffffffffffeULL) - h3;
    h[4] = (f[4] + 0xffffffffffffeULL) - h4;
}

static void
fe25519_copy(fe25519 h, const fe25519 f)
{
    memcpy(h, f, 5 * sizeof h[0]);
}

static void
fe25519_cswap(fe25519 f, fe25519 g, unsigned int b)
{
    uint64_t mask = (uint64_t) (-(int64_t) b);
    uint64_t x0 = (f[0] ^ g[0]) & mask;
    uint64_t x1 = (f[1] ^ g[1]) & mask;
    uint64_t x2 = (f[2] ^ g[2]) & mask;
    uint64_t x3 = (f[3] ^ g[3]) & mask;
    uint64_t x4 = (f[4] ^ g[4]) & mask;

    f[0] ^= x0; g[0] ^= x0;
    f[1] ^= x1; g[1] ^= x1;
    f[2] ^= x2; g[2] ^= x2;
    f[3] ^= x3; g[3] ^= x3;
    f[4] ^= x4; g[4] ^= x4;
}

static void
fe25519_mul(fe25519 h, const fe25519 f, const fe25519 g)
{
    const uint64_t mask = 0x7ffffffffffffULL;
    u128 r0, r1, r2, r3, r4;
    u128 f0, f1, f2, f3, f4;
    u128 f1_19, f2_19, f3_19, f4_19;
    u128 g0, g1, g2, g3, g4;
    uint64_t r00, r01, r02, r03, r04;
    uint64_t carry;

    f0 = (u128) f[0];
    f1 = (u128) f[1];
    f2 = (u128) f[2];
    f3 = (u128) f[3];
    f4 = (u128) f[4];

    g0 = (u128) g[0];
    g1 = (u128) g[1];
    g2 = (u128) g[2];
    g3 = (u128) g[3];
    g4 = (u128) g[4];

    f1_19 = 19ULL * f1;
    f2_19 = 19ULL * f2;
    f3_19 = 19ULL * f3;
    f4_19 = 19ULL * f4;

    r0 = f0 * g0 + f1_19 * g4 + f2_19 * g3 + f3_19 * g2 + f4_19 * g1;
    r1 = f0 * g1 +    f1 * g0 + f2_19 * g4 + f3_19 * g3 + f4_19 * g2;
    r2 = f0 * g2 +    f1 * g1 +    f2 * g0 + f3_19 * g4 + f4_19 * g3;
    r3 = f0 * g3 +    f1 * g2 +    f2 * g1 +    f3 * g0 + f4_19 * g4;
    r4 = f0 * g4 +    f1 * g3 +    f2 * g2 +    f3 * g1 +    f4 * g0;

    r00 = ((uint64_t) r0) & mask;
    carry = (uint64_t) (r0 >> 51);
    r1 += carry;
    r01 = ((uint64_t) r1) & mask;
    carry = (uint64_t) (r1 >> 51);
    r2 += carry;
    r02 = ((uint64_t) r2) & mask;
    carry = (uint64_t) (r2 >> 51);
    r3 += carry;
    r03 = ((uint64_t) r3) & mask;
    carry = (uint64_t) (r3 >> 51);
    r4 += carry;
    r04 = ((uint64_t) r4) & mask;
    carry = (uint64_t) (r4 >> 51);
    r00 += 19ULL * carry;
    carry = r00 >> 51;
    r00 &= mask;
    r01 += carry;
    carry = r01 >> 51;
    r01 &= mask;
    r02 += carry;

    h[0] = r00;
    h[1] = r01;
    h[2] = r02;
    h[3] = r03;
    h[4] = r04;
}

static void
fe25519_sq(fe25519 h, const fe25519 f)
{
    const uint64_t mask = 0x7ffffffffffffULL;
    u128 r0, r1, r2, r3, r4;
    u128 f0, f1, f2, f3, f4;
    u128 f0_2, f1_2, f1_38, f2_38, f3_38, f3_19, f4_19;
    uint64_t r00, r01, r02, r03, r04;
    uint64_t carry;

    f0 = (u128) f[0];
    f1 = (u128) f[1];
    f2 = (u128) f[2];
    f3 = (u128) f[3];
    f4 = (u128) f[4];

    f0_2 = f0 << 1;
    f1_2 = f1 << 1;

    f1_38 = 38ULL * f1;
    f2_38 = 38ULL * f2;
    f3_38 = 38ULL * f3;

    f3_19 = 19ULL * f3;
    f4_19 = 19ULL * f4;

    r0 =   f0 * f0 + f1_38 * f4 + f2_38 * f3;
    r1 = f0_2 * f1 + f2_38 * f4 + f3_19 * f3;
    r2 = f0_2 * f2 +    f1 * f1 + f3_38 * f4;
    r3 = f0_2 * f3 +  f1_2 * f2 + f4_19 * f4;
    r4 = f0_2 * f4 +  f1_2 * f3 +    f2 * f2;

    r00 = ((uint64_t) r0) & mask;
    carry = (uint64_t) (r0 >> 51);
    r1 += carry;
    r01 = ((uint64_t) r1) & mask;
    carry = (uint64_t) (r1 >> 51);
    r2 += carry;
    r02 = ((uint64_t) r2) & mask;
    carry = (uint64_t) (r2 >> 51);
    r3 += carry;
    r03 = ((uint64_t) r3) & mask;
    carry = (uint64_t) (r3 >> 51);
    r4 += carry;
    r04 = ((uint64_t) r4) & mask;
    carry = (uint64_t) (r4 >> 51);
    r00 += 19ULL * carry;
    carry = r00 >> 51;
    r00 &= mask;
    r01 += carry;
    carry = r01 >> 51;
    r01 &= mask;
    r02 += carry;

    h[0] = r00;
    h[1] = r01;
    h[2] = r02;
    h[3] = r03;
    h[4] = r04;
}

static void
fe25519_mul32(fe25519 h, const fe25519 f, uint32_t n)
{
    const uint64_t mask = 0x7ffffffffffffULL;
    u128 a;
    u128 sn = (u128) n;
    uint64_t h0, h1, h2, h3, h4;

    a = f[0] * sn;
    h0 = ((uint64_t) a) & mask;
    a = f[1] * sn + ((uint64_t) (a >> 51));
    h1 = ((uint64_t) a) & mask;
    a = f[2] * sn + ((uint64_t) (a >> 51));
    h2 = ((uint64_t) a) & mask;
    a = f[3] * sn + ((uint64_t) (a >> 51));
    h3 = ((uint64_t) a) & mask;
    a = f[4] * sn + ((uint64_t) (a >> 51));
    h4 = ((uint64_t) a) & mask;

    h0 += ((uint64_t) (a >> 51)) * 19ULL;

    h[0] = h0;
    h[1] = h1;
    h[2] = h2;
    h[3] = h3;
    h[4] = h4;
}

static void
fe25519_frombytes(fe25519 h, const unsigned char *s)
{
    const uint64_t mask = 0x7ffffffffffffULL;

    h[0] = load64_le(s + 0) & mask;
    h[1] = (load64_le(s + 6) >> 3) & mask;
    h[2] = (load64_le(s + 12) >> 6) & mask;
    h[3] = (load64_le(s + 19) >> 1) & mask;
    h[4] = (load64_le(s + 24) >> 12) & mask;
}

static void
fe25519_reduce(fe25519 h, const fe25519 f)
{
    const uint64_t mask = 0x7ffffffffffffULL;
    u128 t0 = f[0];
    u128 t1 = f[1];
    u128 t2 = f[2];
    u128 t3 = f[3];
    u128 t4 = f[4];

    t1 += t0 >> 51; t0 &= mask;
    t2 += t1 >> 51; t1 &= mask;
    t3 += t2 >> 51; t2 &= mask;
    t4 += t3 >> 51; t3 &= mask;
    t0 += 19 * (t4 >> 51); t4 &= mask;

    t1 += t0 >> 51; t0 &= mask;
    t2 += t1 >> 51; t1 &= mask;
    t3 += t2 >> 51; t2 &= mask;
    t4 += t3 >> 51; t3 &= mask;
    t0 += 19 * (t4 >> 51); t4 &= mask;

    t0 += 19ULL;

    t1 += t0 >> 51; t0 &= mask;
    t2 += t1 >> 51; t1 &= mask;
    t3 += t2 >> 51; t2 &= mask;
    t4 += t3 >> 51; t3 &= mask;
    t0 += 19ULL * (t4 >> 51); t4 &= mask;

    t0 += 0x8000000000000ULL - 19ULL;
    t1 += 0x8000000000000ULL - 1ULL;
    t2 += 0x8000000000000ULL - 1ULL;
    t3 += 0x8000000000000ULL - 1ULL;
    t4 += 0x8000000000000ULL - 1ULL;

    t1 += t0 >> 51; t0 &= mask;
    t2 += t1 >> 51; t1 &= mask;
    t3 += t2 >> 51; t2 &= mask;
    t4 += t3 >> 51; t3 &= mask;
    t4 &= mask;

    h[0] = (uint64_t) t0;
    h[1] = (uint64_t) t1;
    h[2] = (uint64_t) t2;
    h[3] = (uint64_t) t3;
    h[4] = (uint64_t) t4;
}

static void
fe25519_tobytes(unsigned char *s, const fe25519 h)
{
    fe25519 t;
    uint64_t t0, t1, t2, t3;

    fe25519_reduce(t, h);
    t0 = t[0] | (t[1] << 51);
    t1 = (t[1] >> 13) | (t[2] << 38);
    t2 = (t[2] >> 26) | (t[3] << 25);
    t3 = (t[3] >> 39) | (t[4] << 12);
    store64_le(s + 0, t0);
    store64_le(s + 8, t1);
    store64_le(s + 16, t2);
    store64_le(s + 24, t3);
}

static void
fe25519_invert(fe25519 out, const fe25519 z)
{
    fe25519 t0, t1, t2, t3;
    int i;

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

static int
has_small_order(const unsigned char s[32])
{
    static const unsigned char blocklist[7][32] = {
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
          0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
          0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00 },
        { 0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1,
          0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c,
          0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57 },
        { 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        { 0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        { 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }
    };
    unsigned char c[7] = { 0 };
    unsigned int k = 0;
    size_t i, j;

    for (j = 0; j < 31; j++) {
        for (i = 0; i < 7; i++) {
            c[i] |= s[j] ^ blocklist[i][j];
        }
    }
    for (i = 0; i < 7; i++) {
        c[i] |= (s[j] & 0x7f) ^ blocklist[i][j];
        k |= (unsigned int) (c[i] - 1U);
    }
    return (int) ((k >> 8) & 1U);
}

int
tyr_x25519_ref10_scalarmult(unsigned char *q,
                            const unsigned char *n,
                            const unsigned char *p)
{
    unsigned char t[32];
    unsigned int i;
    fe25519 x1, x2, x3, z2, z3;
    fe25519 a, b, aa, bb, e, da, cb;
    int pos;
    unsigned int swap = 0;
    unsigned int bit = 0;

    if (has_small_order(p)) {
        return -1;
    }
    for (i = 0; i < 32; i++) {
        t[i] = n[i];
    }
    t[0] &= 248;
    t[31] &= 127;
    t[31] |= 64;

    fe25519_frombytes(x1, p);
    fe25519_1(x2);
    fe25519_0(z2);
    fe25519_copy(x3, x1);
    fe25519_1(z3);

    for (pos = 254; pos >= 0; --pos) {
        bit = t[pos / 8] >> (pos & 7);
        bit &= 1;
        swap ^= bit;
        fe25519_cswap(x2, x3, swap);
        fe25519_cswap(z2, z3, swap);
        swap = bit;
        fe25519_add(a, x2, z2);
        fe25519_sub(b, x2, z2);
        fe25519_sq(aa, a);
        fe25519_sq(bb, b);
        fe25519_mul(x2, aa, bb);
        fe25519_sub(e, aa, bb);
        fe25519_sub(da, x3, z3);
        fe25519_mul(da, da, a);
        fe25519_add(cb, x3, z3);
        fe25519_mul(cb, cb, b);
        fe25519_add(x3, da, cb);
        fe25519_sq(x3, x3);
        fe25519_sub(z3, da, cb);
        fe25519_sq(z3, z3);
        fe25519_mul(z3, z3, x1);
        fe25519_mul32(z2, e, 121666);
        fe25519_add(z2, z2, bb);
        fe25519_mul(z2, z2, e);
    }
    fe25519_cswap(x2, x3, swap);
    fe25519_cswap(z2, z3, swap);

    fe25519_invert(z2, z2);
    fe25519_mul(x2, x2, z2);
    fe25519_tobytes(q, x2);
    secure_memzero(t, sizeof t);

    return 0;
}

int
tyr_x25519_ref10_scalarmult_base(unsigned char *q, const unsigned char *n)
{
    static const unsigned char basepoint[32] = {
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    return tyr_x25519_ref10_scalarmult(q, n, basepoint);
}
