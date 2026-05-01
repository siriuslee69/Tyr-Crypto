#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../../../../submodules/pqclean/common/aes.h"

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#ifndef BCRYPT_USE_SYSTEM_PREFERRED_RNG
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
#endif
#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif
#endif

#if defined(_MSC_VER)
#define TYR_THREAD_LOCAL __declspec(thread)
#else
#define TYR_THREAD_LOCAL __thread
#endif

static TYR_THREAD_LOCAL const uint8_t *tyr_pq_feed = 0;
static TYR_THREAD_LOCAL size_t tyr_pq_feed_len = 0;
static TYR_THREAD_LOCAL size_t tyr_pq_feed_pos = 0;

typedef struct {
    uint8_t key[32];
    uint8_t v[16];
    int reseed_counter;
    int ready;
} tyr_pq_drbg_ctx;

static TYR_THREAD_LOCAL tyr_pq_drbg_ctx tyr_pq_drbg;

static void tyr_pq_secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *) ptr;
    while (len > 0) {
        *p++ = 0;
        len--;
    }
}

static void tyr_pq_drbg_clear(void) {
    tyr_pq_secure_zero(&tyr_pq_drbg, sizeof(tyr_pq_drbg));
}

void tyr_pq_randombytes_set(const uint8_t *feed, size_t feed_len) {
    tyr_pq_drbg_clear();
    tyr_pq_feed = feed;
    tyr_pq_feed_len = feed_len;
    tyr_pq_feed_pos = 0;
}

void tyr_pq_randombytes_clear(void) {
    tyr_pq_feed = 0;
    tyr_pq_feed_len = 0;
    tyr_pq_feed_pos = 0;
    tyr_pq_drbg_clear();
}

size_t tyr_pq_randombytes_remaining(void) {
    if (tyr_pq_feed_pos >= tyr_pq_feed_len) {
        return 0;
    }
    return tyr_pq_feed_len - tyr_pq_feed_pos;
}

static void tyr_pq_drbg_increment_v(uint8_t v[16]) {
    int j = 15;
    for (j = 15; j >= 0; j--) {
        if (v[j] == 0xff) {
            v[j] = 0x00;
        } else {
            v[j]++;
            break;
        }
    }
}

static void tyr_pq_aes256_ecb(uint8_t *key, uint8_t *ctr, uint8_t *buffer) {
    aes256ctx ctx;
    aes256_ecb_keyexp(&ctx, key);
    aes256_ecb(buffer, ctr, 1, &ctx);
    aes256_ctx_release(&ctx);
}

static void tyr_pq_drbg_update(const uint8_t *provided_data) {
    uint8_t temp[48];
    int i = 0;

    for (i = 0; i < 3; i++) {
        tyr_pq_drbg_increment_v(tyr_pq_drbg.v);
        tyr_pq_aes256_ecb(tyr_pq_drbg.key, tyr_pq_drbg.v, temp + 16 * i);
    }
    if (provided_data != 0) {
        for (i = 0; i < 48; i++) {
            temp[i] ^= provided_data[i];
        }
    }
    memcpy(tyr_pq_drbg.key, temp, 32);
    memcpy(tyr_pq_drbg.v, temp + 32, 16);
    tyr_pq_secure_zero(temp, sizeof(temp));
}

void tyr_pq_randombytes_seed_kat(const uint8_t *seed48) {
    uint8_t seed_material[48];

    tyr_pq_feed = 0;
    tyr_pq_feed_len = 0;
    tyr_pq_feed_pos = 0;
    tyr_pq_drbg_clear();
    if (seed48 == 0) {
        return;
    }
    memcpy(seed_material, seed48, 48);
    tyr_pq_drbg_update(seed_material);
    tyr_pq_drbg.reseed_counter = 1;
    tyr_pq_drbg.ready = 1;
    tyr_pq_secure_zero(seed_material, sizeof(seed_material));
}

static void tyr_pq_drbg_randombytes(uint8_t *out, size_t out_len) {
    uint8_t block[16];
    size_t offset = 0;
    size_t take = 0;

    while (out_len > 0) {
        tyr_pq_drbg_increment_v(tyr_pq_drbg.v);
        tyr_pq_aes256_ecb(tyr_pq_drbg.key, tyr_pq_drbg.v, block);
        take = out_len > 16 ? 16 : out_len;
        memcpy(out + offset, block, take);
        offset += take;
        out_len -= take;
    }
    tyr_pq_drbg_update(0);
    tyr_pq_drbg.reseed_counter++;
    tyr_pq_secure_zero(block, sizeof(block));
}

static void tyr_pq_os_randombytes(uint8_t *out, size_t out_len) {
#if defined(_WIN32)
    while (out_len > 0) {
        ULONG chunk = out_len > 0x40000000u ? 0x40000000u : (ULONG) out_len;
        if (BCryptGenRandom(NULL, out, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
            memset(out, 0, out_len);
            return;
        }
        out += chunk;
        out_len -= chunk;
    }
#else
    size_t off = 0;
#if defined(__linux__)
    while (off < out_len) {
        ssize_t got = getrandom(out + off, out_len - off, 0);
        if (got > 0) {
            off += (size_t) got;
            continue;
        }
        if (errno != EINTR) {
            break;
        }
    }
    if (off == out_len) {
        return;
    }
#endif
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        memset(out + off, 0, out_len - off);
        return;
    }
    while (off < out_len) {
        ssize_t got = read(fd, out + off, out_len - off);
        if (got > 0) {
            off += (size_t) got;
            continue;
        }
        if (errno != EINTR) {
            break;
        }
    }
    close(fd);
    if (off < out_len) {
        memset(out + off, 0, out_len - off);
    }
#endif
}

static void tyr_pq_randombytes_fill(uint8_t *out, size_t out_len) {
    size_t take = 0;
    if (tyr_pq_feed != 0 && tyr_pq_feed_pos < tyr_pq_feed_len) {
        take = tyr_pq_feed_len - tyr_pq_feed_pos;
        if (take > out_len) {
            take = out_len;
        }
        memcpy(out, tyr_pq_feed + tyr_pq_feed_pos, take);
        tyr_pq_feed_pos += take;
        out += take;
        out_len -= take;
    }
    if (out_len > 0 && tyr_pq_drbg.ready) {
        tyr_pq_drbg_randombytes(out, out_len);
        return;
    }
    if (out_len > 0) {
        tyr_pq_os_randombytes(out, out_len);
    }
}

int PQCLEAN_randombytes(uint8_t *out, size_t out_len) {
    tyr_pq_randombytes_fill(out, out_len);
    return 0;
}

void randombytes(uint8_t *out, size_t out_len) {
    tyr_pq_randombytes_fill(out, out_len);
}
