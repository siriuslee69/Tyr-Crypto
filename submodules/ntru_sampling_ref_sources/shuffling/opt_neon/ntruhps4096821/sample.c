// clang-format off

#include <arm_acle.h>
#include <arm_neon.h>
#include "sample.h"

void sample_fg(poly *f, poly *g, const unsigned char uniformbytes[NTRU_SAMPLE_FG_BYTES])
{
#ifdef NTRU_HRSS
  sample_iid_plus(f,uniformbytes);
  sample_iid_plus(g,uniformbytes+NTRU_SAMPLE_IID_BYTES);
#endif

#ifdef NTRU_HPS
  sample_iid(f,uniformbytes);
  sample_fixed_type(g,uniformbytes+NTRU_SAMPLE_IID_BYTES);
#endif
}

void sample_rm(poly *r, poly *m, const unsigned char uniformbytes[NTRU_SAMPLE_RM_BYTES])
{
#ifdef NTRU_HRSS
  sample_iid(r,uniformbytes);
  sample_iid(m,uniformbytes+NTRU_SAMPLE_IID_BYTES);
#endif

#ifdef NTRU_HPS
  sample_iid(r,uniformbytes);
  sample_fixed_type(m,uniformbytes+NTRU_SAMPLE_IID_BYTES);
#endif
}

#ifdef NTRU_HRSS
void sample_iid_plus(poly *r, const unsigned char uniformbytes[NTRU_SAMPLE_IID_BYTES])
{
  /* Sample r using sample_iid then conditionally flip    */
  /* signs of even index coefficients so that <x*r, r> >= 0.      */

  int i;
  uint16_t s = 0;

  sample_iid(r, uniformbytes);

  /* Map {0,1,2} -> {0, 1, 2^16 - 1} */
  for(i=0; i<NTRU_N-1; i++)
    r->coeffs[i] = r->coeffs[i] | (-(r->coeffs[i]>>1));

  /* s = <x*r, r>.  (r[n-1] = 0) */
  for(i=0; i<NTRU_N-1; i++)
    s += (uint16_t)((uint32_t)r->coeffs[i + 1] * (uint32_t)r->coeffs[i]);

  /* Extract sign of s (sign(0) = 1) */
  s = 1 | (-(s>>15));

  for(i=0; i<NTRU_N; i+=2)
    r->coeffs[i] = (uint16_t)((uint32_t)s * (uint32_t)r->coeffs[i]);

  /* Map {0,1,2^16-1} -> {0, 1, 2} */
  for(i=0; i<NTRU_N; i++)
    r->coeffs[i] = 3 & (r->coeffs[i] ^ (r->coeffs[i]>>15));
}
#endif

#ifdef NTRU_HPS
static inline uint16x8_t simd_rejsamplingmod(int i, int *j, uint16x8_t vsi[], uint16x8_t vsq, const uint16_t u[],
                                             const uint16_t vt[]) {
  const uint16x8_t vsq_delta = {8, 8, 8, 8, 8, 8, 8, 8};
  uint32x4_t vm1q, vm2q;
  uint16x8_t vrndq, vlq, vcmpq, vcmp2q, vtq;
  uint8x16_t vtmpq;
  uint8x8_t vres;
  uint64_t res;
  int k;

  vrndq = vld1q_u16(&u[i]);
  vtq = vld1q_u16(&vt[i]);

  vm1q = vmull_u16(vget_low_u16(vrndq), vget_low_u16(vsq));
  vm2q = vmull_high_u16(vrndq, vsq);
  vsq = vsubq_u16(vsq, vsq_delta);

  vlq = vuzp1q_u16(vreinterpretq_u16_u32(vm1q), vreinterpretq_u16_u32(vm2q));
  vsi[0] = vuzp2q_u16(vreinterpretq_u16_u32(vm1q), vreinterpretq_u16_u32(vm2q));

  vsi[0] = vreinterpretq_u16_s16(vnegq_s16(vreinterpretq_s16_u16(vsi[0])));

  vcmpq = vcltq_u16(vlq, vtq);

  vrndq = vld1q_u16(&u[i + 8]);
  vtq = vld1q_u16(&vt[i + 8]);

  vm1q = vmull_u16(vget_low_u16(vrndq), vget_low_u16(vsq));
  vm2q = vmull_high_u16(vrndq, vsq);
  vsq = vsubq_u16(vsq, vsq_delta);

  vlq = vuzp1q_u16(vreinterpretq_u16_u32(vm1q), vreinterpretq_u16_u32(vm2q));
  vsi[1] = vuzp2q_u16(vreinterpretq_u16_u32(vm1q), vreinterpretq_u16_u32(vm2q));

  vsi[1] = vreinterpretq_u16_s16(vnegq_s16(vreinterpretq_s16_u16(vsi[1])));

  vcmp2q = vcltq_u16(vlq, vtq);

  vtmpq = vuzp1q_u8(vreinterpretq_u8_u16(vcmpq), vreinterpretq_u8_u16(vcmp2q));
  vres = vshrn_n_u16(vreinterpretq_u16_u8(vtmpq), 4);
  res = vget_lane_u64(vreinterpret_u64_u8(vres), 0);

  if (res != 0) {
    uint32_t m;
    uint16_t s, t, l;

    res = __rbitll(res);

    do {
      k = __builtin_clzl(res) / 4;

      s = NTRU_N - 1 - (i + k);
      t = vt[i + k];
      do {
        m = (uint32_t)u[(*j)++] * s;
        l = m;
      }
      while (l < t);
      vsi[k / 8][k % 8] = -(m >> 16);

      res &= ~(0xFUL << (4 * (15 - k)));
    }
    while (res != 0);
  }

  return vsq;
}

void sample_fixed_type(poly *r, const unsigned char u[NTRU_SAMPLE_FT_BYTES]) {
  const uint16_t d[] = {820, 819, 818, 817, 816, 815, 814, 813};
  const uint16_t vt[] = {
    756, 16,  96,  176, 256, 336, 416, 496, 576, 656, 736, 7,   88,  169, 250, 331,
    412, 493, 574, 655, 736, 18,  100, 182, 264, 346, 428, 510, 592, 674, 756, 49,
    132, 215, 298, 381, 464, 547, 630, 713, 16,  100, 184, 268, 352, 436, 520, 604,
    688, 1,   86,  171, 256, 341, 426, 511, 596, 681, 4,   90,  176, 262, 348, 434,
    520, 606, 692, 25,  112, 199, 286, 373, 460, 547, 634, 721, 64,  152, 240, 328,
    416, 504, 592, 680, 32,  121, 210, 299, 388, 477, 566, 655, 16,  106, 196, 286,
    376, 466, 556, 646, 16,  107, 198, 289, 380, 471, 562, 653, 32,  124, 216, 308,
    400, 492, 584, 676, 64,  157, 250, 343, 436, 529, 622, 18,  112, 206, 300, 394,
    488, 582, 676, 81,  176, 271, 366, 461, 556, 651, 64,  160, 256, 352, 448, 544,
    640, 61,  158, 255, 352, 449, 546, 643, 72,  170, 268, 366, 464, 562, 660, 97,
    196, 295, 394, 493, 592, 36,  136, 236, 336, 436, 536, 636, 88,  189, 290, 391,
    492, 593, 52,  154, 256, 358, 460, 562, 28,  131, 234, 337, 440, 543, 16,  120,
    224, 328, 432, 536, 16,  121, 226, 331, 436, 541, 28,  134, 240, 346, 452, 558,
    52,  159, 266, 373, 480, 587, 88,  196, 304, 412, 520, 27,  136, 245, 354, 463,
    572, 86,  196, 306, 416, 526, 46,  157, 268, 379, 490, 16,  128, 240, 352, 464,
    576, 109, 222, 335, 448, 561, 100, 214, 328, 442, 556, 101, 216, 331, 446, 561,
    112, 228, 344, 460, 16,  133, 250, 367, 484, 46,  164, 282, 400, 518, 86,  205,
    324, 443, 16,  136, 256, 376, 496, 75,  196, 317, 438, 22,  144, 266, 388, 510,
    100, 223, 346, 469, 64,  188, 312, 436, 36,  161, 286, 411, 16,  142, 268, 394,
    4,   131, 258, 385, 0,   128, 256, 384, 4,   133, 262, 391, 16,  146, 276, 406,
    36,  167, 298, 429, 64,  196, 328, 460, 100, 233, 366, 10,  144, 278, 412, 61,
    196, 331, 466, 120, 256, 392, 50,  187, 324, 461, 124, 262, 400, 67,  206, 345,
    16,  156, 296, 436, 112, 253, 394, 74,  216, 358, 42,  185, 328, 16,  160, 304,
    448, 141, 286, 431, 128, 274, 420, 121, 268, 415, 120, 268, 416, 125, 274, 423,
    136, 286, 2,   153, 304, 24,  176, 328, 52,  205, 358, 86,  240, 394, 126, 281,
    16,  172, 328, 67,  224, 381, 124, 282, 28,  187, 346, 96,  256, 9,   170, 331,
    88,  250, 10,  173, 336, 100, 264, 31,  196, 361, 132, 298, 72,  239, 16,  184,
    352, 133, 302, 86,  256, 43,  214, 4,   176, 348, 142, 315, 112, 286, 86,  261,
    64,  240, 46,  223, 32,  210, 22,  201, 16,  196, 14,  195, 16,  198, 22,  205,
    32,  216, 46,  231, 64,  250, 86,  273, 112, 300, 142, 331, 176, 23,  214, 64,
    256, 109, 302, 158, 16,  211, 72,  268, 132, 329, 196, 65,  264, 136, 10,  211,
    88,  290, 170, 52,  256, 141, 28,  234, 124, 16,  224, 119, 16,  226, 126, 28,
    240, 145, 52,  266, 176, 88,  2,   219, 136, 55,  274, 196, 120, 46,  268, 197,
    128, 61,  286, 222, 160, 100, 42,  271, 216, 163, 112, 63,  16,  250, 206, 164,
    124, 86,  50,  16,  256, 225, 196, 169, 144, 121, 100, 81,  64,  49,  36,  25,
    16,  9,   4,   1,   0,   1,   4,   9,   16,  25,  36,  49,  64,  81,  100, 121,
    144, 169, 196, 225, 16,  50,  86,  124, 164, 206, 16,  63,  112, 163, 216, 42,
    100, 160, 222, 61,  128, 197, 46,  120, 196, 55,  136, 2,   88,  176, 52,  145,
    28,  126, 16,  119, 16,  124, 28,  141, 52,  170, 88,  10,  136, 65,  196, 132,
    72,  16,  158, 109, 64,  23,  176, 142, 112, 86,  64,  46,  32,  22,  16,  14,
    16,  22,  32,  46,  64,  86,  112, 142, 4,   43,  86,  133, 16,  72,  132, 31,
    100, 10,  88,  9,   96,  28,  124, 67,  16,  126, 86,  52,  24,  2,   136, 125,
    120, 121, 128, 141, 16,  42,  74,  112, 16,  67,  124, 50,  120, 61,  10,  100,
    64,  36,  16,  4,   0,   4,   16,  36,  64,  100, 22,  75,  16,  86,  46,  16,
    112, 101, 100, 109, 16,  46,  86,  27,  88,  52,  28,  16,  16,  28,  52,  88,
    36,  97,  72,  61,  64,  81,  18,  64,  32,  16,  16,  32,  64,  25,  4,   1,
    16,  49,  18,  7,   16,  45,  16,  9,   24,  61,  46,  55,  16,  3,   16,  55,
    52,  10,  64,  16,  0,   16,  2,   22,  16,  46,  54,  43,  16,  31,  34,  28,
    16,  1,   36,  23,  16,  18,  32,  16,  20,  4,   16,  18,  16,  16,  24,  9,
    16,  16,  18,  31,  0,   2,   16,  25,  16,  7,   16,  11,  16,  9,   20,  16,
    16,  5,   16,  1,   0,   1,   2,   3,   4,   9,   6,   7,   0,   2,   4,   1,
    0,   1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0
  };
  volatile int16_t shuffle_indices[16];  // Avoids slow move from SIMD to scalar register file
  uint16x8_t vsi[2], vsq = vld1q_u16(d);
  int i, j = NTRU_N - 1, l, t, p;
  int n_unroll = NTRU_N - (NTRU_N % 16);
  int c0 = -(NTRU_N - 1 - NTRU_WEIGHT), c01 = -(NTRU_N - 1 - NTRU_WEIGHT / 2);

  vsq = simd_rejsamplingmod(0, &j, vsi, vsq, (const uint16_t*)u, vt);

  vst1q_s16((int16_t *)&shuffle_indices[0], vreinterpretq_s16_u16(vsi[0]));
  vst1q_s16((int16_t *)&shuffle_indices[8], vreinterpretq_s16_u16(vsi[1]));

  for (i = 0; i < n_unroll; i += 16) {
    vsq = simd_rejsamplingmod(i + 16, &j, vsi, vsq, (const uint16_t*)u, vt);

    for (l = 0; l < 16; l++) {
      p = shuffle_indices[l];

      asm("subs   %w[t],  %w[c0], %w[p]         \n"
          "cinc  %w[c0],  %w[c0],    lt         \n"
          "add  %w[r_i], %w[two], %w[t], asr #31\n"
          "subs   %w[t],  %w[c1], %w[p]         \n"
          "cinc  %w[c1],  %w[c1],    lt         \n"
          "add  %w[r_i], %w[r_i], %w[t], asr #31\n"
          : [c0] "+&r"(c0), [c1] "+&r"(c01), [r_i] "=&r"(r->coeffs[i + l]), [t] "=&r"(t)
          : [p] "r"(p), [two] "r"(2)
          : "cc");
    }

    vst1q_s16((int16_t *)&shuffle_indices[0], vreinterpretq_s16_u16(vsi[0]));
    vst1q_s16((int16_t *)&shuffle_indices[8], vreinterpretq_s16_u16(vsi[1]));
  }

  for (; i < NTRU_N; i++) {
    p = shuffle_indices[i - n_unroll];

    asm("subs   %w[t],  %w[c0], %w[p]         \n"
        "cinc  %w[c0],  %w[c0],    lt         \n"
        "add  %w[r_i], %w[two], %w[t], asr #31\n"
        "subs   %w[t],  %w[c1], %w[p]         \n"
        "cinc  %w[c1],  %w[c1],    lt         \n"
        "add  %w[r_i], %w[r_i], %w[t], asr #31\n"
        : [c0] "+&r"(c0), [c1] "+&r"(c01), [r_i] "=&r"(r->coeffs[i]), [t] "=&r"(t)
        : [p] "r"(p), [two] "r"(2)
        : "cc");
  }

  r->coeffs[NTRU_N - 1] = 0;
}

#endif
// clang-format on
