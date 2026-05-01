// clang-format off

#include "sample.h"

#define ISOCHRONOUS_SAMPLING

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
// Unlike Algorithm 5 in the paper, we use the batch random number generation idea, discussed in Section 4. Moreover,
// although not required in non-SIMD versions, we use disjoint ranges in the random number array for the initial
// sampling and the rejection sampling fixup procedure, as discussed in "SIMD implementation of Algorithm 5" in
// Section 4, to ensure interoperability of KATs between the scalar and SIMD versions.
void rejsamplingmod(int16_t shuffle_indices[], const uint16_t u[NTRU_SAMPLE_FT_BYTES / 2]) {
  int i, j = NTRU_N - 1;

  for (i = 0; i < NTRU_N - 1; i++)
  {
    uint32_t m;
    uint16_t s, t, l;

    s = NTRU_N - 1 - i;
    t = 65536 % s;

    m = (uint32_t)u[i] * s;
    l = m;

    while (l < t)
    {
      m = (uint32_t)u[j++] * s;
      l = m;
    }

    shuffle_indices[i] = m >> 16;
  }
}

void sample_fixed_type(poly *r, const unsigned char u[NTRU_SAMPLE_FT_BYTES]) {
  int16_t shuffle_indices[NTRU_N - 1];

  rejsamplingmod(shuffle_indices, (const uint16_t*)u);

#ifdef ISOCHRONOUS_SAMPLING
  int c0 = NTRU_N - 1 - NTRU_WEIGHT, c01 = NTRU_N - 1 - NTRU_WEIGHT / 2;

  for (int i = 0; i < NTRU_N - 1; i++)
  {
    int t0, t1;
    int p = shuffle_indices[i];

    t0 = (p - c0) >> 31;
    t1 = (p - c01) >> 31;

    c0 += t0;
    c01 += t1;

    r->coeffs[i] = 2 + t0 + t1;
  }
#else
  int c0 = NTRU_N - 1 - NTRU_WEIGHT, c1 = NTRU_WEIGHT / 2;

  for (int i = 0; i < NTRU_N - 1; i++)
  {
    int16_t p = shuffle_indices[i];
    if (p < c0)
    {
      r->coeffs[i] = 0;
      c0--;
    }
    else if (p < c0 + c1)
    {
      r->coeffs[i] = 1;
      c1--;
    }
    else
    {
      r->coeffs[i] = 2;
    }
  }
#endif

  r->coeffs[NTRU_N-1] = 0;
}
#endif
// clang-format on
