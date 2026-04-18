#include <stdint.h>
#include <string.h>

typedef int16_t int16;
typedef int32_t int32;

static inline int32 negative_mask32(int32 x) {
    return x >> 31;
}

static inline int16 negative_mask16(int16 x) {
    return x >> 15;
}

static inline int16 nonzero_mask16(int16 x) {
    return negative_mask16(x) | negative_mask16(-x);
}

static inline int32 int32_min(int32 x, int32 y) {
    int32 xy = y ^ x;
    int32 z = y - x;
    z ^= xy & (z ^ y);
    z = negative_mask32(z);
    z &= xy;
    return x ^ z;
}

#define INT32_MINMAX(a,b) \
    do { \
        int32 ab = (b) ^ (a); \
        int32 c = (b) - (a); \
        c ^= ab & ((c) ^ (b)); \
        c >>= 31; \
        c &= ab; \
        (a) ^= c; \
        (b) ^= c; \
    } while (0)

static void int32_sort(int32 *x, long long n) {
    long long top, p, q, r, i;

    if (n < 2) {
        return;
    }
    top = 1;
    while (top < n - top) {
        top += top;
    }

    for (p = top; p > 0; p >>= 1) {
        for (i = 0; i < n - p; ++i) {
            if (!(i & p)) {
                INT32_MINMAX(x[i], x[i + p]);
            }
        }
        i = 0;
        for (q = top; q > p; q >>= 1) {
            for (; i < n - q; ++i) {
                if (!(i & p)) {
                    int32 a = x[i + p];
                    for (r = q; r > p; r >>= 1) {
                        INT32_MINMAX(a, x[i + r]);
                    }
                    x[i + p] = a;
                }
            }
        }
    }
}

static void cbrecursion(unsigned char *out, long long pos, long long step,
    const int16 *pi, long long w, long long n, int32 *temp) {
#define A temp
#define B (temp + n)
#define q ((int16 *) (temp + n + n / 4))
    long long x, y, i, j, k;

    if (w == 1) {
        out[pos >> 3] ^= pi[0] << (pos & 7);
        return;
    }

    for (x = 0; x < n; ++x) {
        A[x] = ((pi[x] ^ 1) << 16) | pi[x ^ 1];
    }
    int32_sort(A, n);

    for (x = 0; x < n; ++x) {
        int32 Ax = A[x];
        int32 px = Ax & 0xffff;
        int32 cx = int32_min(px, (int32)x);
        B[x] = (px << 16) | cx;
    }

    for (x = 0; x < n; ++x) {
        A[x] = (int32)((((uint32_t) A[x]) << 16) | x);
    }
    int32_sort(A, n);

    for (x = 0; x < n; ++x) {
        A[x] = (((uint32_t) A[x]) << 16) + (B[x] >> 16);
    }
    int32_sort(A, n);

    if (w <= 10) {
        for (x = 0; x < n; ++x) {
            B[x] = ((A[x] & 0xffff) << 10) | (B[x] & 0x3ff);
        }

        for (i = 1; i < w - 1; ++i) {
            for (x = 0; x < n; ++x) {
                A[x] = (int32)(((B[x] & ~0x3ff) << 6) | x);
            }
            int32_sort(A, n);

            for (x = 0; x < n; ++x) {
                A[x] = ((uint32_t) A[x] << 20) | B[x];
            }
            int32_sort(A, n);

            for (x = 0; x < n; ++x) {
                int32 ppcpx = A[x] & 0xfffff;
                int32 ppcx = (A[x] & 0xffc00) | (B[x] & 0x3ff);
                B[x] = int32_min(ppcx, ppcpx);
            }
        }
        for (x = 0; x < n; ++x) {
            B[x] &= 0x3ff;
        }
    } else {
        for (x = 0; x < n; ++x) {
            B[x] = (((uint32_t) A[x]) << 16) | (B[x] & 0xffff);
        }

        for (i = 1; i < w - 1; ++i) {
            for (x = 0; x < n; ++x) {
                A[x] = (int32)((B[x] & ~0xffff) | x);
            }
            int32_sort(A, n);

            for (x = 0; x < n; ++x) {
                A[x] = (((uint32_t) A[x]) << 16) | (B[x] & 0xffff);
            }

            if (i < w - 2) {
                for (x = 0; x < n; ++x) {
                    B[x] = (A[x] & ~0xffff) | (B[x] >> 16);
                }
                int32_sort(B, n);
                for (x = 0; x < n; ++x) {
                    B[x] = (((uint32_t) B[x]) << 16) | (A[x] & 0xffff);
                }
            }

            int32_sort(A, n);
            for (x = 0; x < n; ++x) {
                int32 cpx = (B[x] & ~0xffff) | (A[x] & 0xffff);
                B[x] = int32_min(B[x], cpx);
            }
        }
        for (x = 0; x < n; ++x) {
            B[x] &= 0xffff;
        }
    }

    for (x = 0; x < n; ++x) {
        A[x] = (int32)((((int32) pi[x]) << 16) + x);
    }
    int32_sort(A, n);

    for (j = 0; j < n / 2; ++j) {
        x = 2 * j;
        int32 fj = B[x] & 1;
        int32 Fx = (int32)(x + fj);
        int32 Fx1 = Fx ^ 1;

        out[pos >> 3] ^= fj << (pos & 7);
        pos += step;

        B[x] = ((uint32_t) A[x] << 16) | Fx;
        B[x + 1] = ((uint32_t) A[x + 1] << 16) | Fx1;
    }

    int32_sort(B, n);

    pos += (2 * w - 3) * step * (n / 2);

    for (k = 0; k < n / 2; ++k) {
        y = 2 * k;
        int32 lk = B[y] & 1;
        int32 Ly = (int32)(y + lk);
        int32 Ly1 = Ly ^ 1;

        out[pos >> 3] ^= lk << (pos & 7);
        pos += step;

        A[y] = (Ly << 16) | (B[y] & 0xffff);
        A[y + 1] = (Ly1 << 16) | (B[y + 1] & 0xffff);
    }

    int32_sort(A, n);

    pos -= (2 * w - 2) * step * (n / 2);

    for (j = 0; j < n / 2; ++j) {
        q[j] = (A[2 * j] & 0xffff) >> 1;
        q[j + n / 2] = (A[2 * j + 1] & 0xffff) >> 1;
    }

    cbrecursion(out, pos, step * 2, q, w - 1, n / 2, temp);
    cbrecursion(out, pos + step, step * 2, q + n / 2, w - 1, n / 2, temp);
#undef A
#undef B
#undef q
}

void tyr_mceliece_controlbits_unchecked(unsigned char *out, const int16 *pi,
    long long w, long long n) {
    int32 temp[2 * 8192];
    memset(out, 0, (size_t)((((2 * w - 1) * n / 2) + 7) / 8));
    cbrecursion(out, 0, 1, pi, w, n, temp);
}
