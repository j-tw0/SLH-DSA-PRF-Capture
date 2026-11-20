#define _CRT_SECURE_NO_WARNINGS
#define SLH_CAPTURE_FIRMWARE_VERSION "2026-07-13-fixed"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "hal.h"
#include "simpleserial.h"

/*
 * ChipWhisperer target for SLH-DSA PRF experiments.
 *
 * This experimental target runs isolated address PRF calls, not full signatures.
 * The host constructs parameter-set-specific FIPS 205 addresses.
 * Compile-time security level is selected through slh_param_config.h:
 *     #define SLH_SECURITY_LEVEL 128
 *     #define SLH_SECURITY_LEVEL 192
 *     #define SLH_SECURITY_LEVEL 256
 *
 * The selected firmware supports both hash families at runtime:
 *   mode = 0 : SLH-DSA-SHA2-{128f,128s,192f,192s,256f,256s} PRF
 *              Trunc_n(SHA-256(PK.seed || zero[64-n] || ADRS_c || SK.seed))
 *   mode = 1 : SLH-DSA-SHAKE-{128f,128s,192f,192s,256f,256s} PRF
 *              SHAKE256(PK.seed || ADRS || SK.seed, n)
 *
 * FIPS 205 uses SHA-256 for PRF for n=16,24,32.  SHA-512 is used by
 * other category-3/5 functions (e.g. H/T_l), but not by PRF_ADDR.
 */

#include "slh_param_config.h"

#if SLH_SECURITY_LEVEL == 128
#define SLH_N              16u
#define SLH_FULL_HEIGHT    66u
#define SLH_D              22u
#define SLH_TREE_HEIGHT    3u
#define SLH_FORS_HEIGHT    6u
#define SLH_FORS_TREES     33u
#elif SLH_SECURITY_LEVEL == 192
#define SLH_N              24u
#define SLH_FULL_HEIGHT    66u
#define SLH_D              22u
#define SLH_TREE_HEIGHT    3u
#define SLH_FORS_HEIGHT    8u
#define SLH_FORS_TREES     33u
#elif SLH_SECURITY_LEVEL == 256
#define SLH_N              32u
#define SLH_FULL_HEIGHT    68u
#define SLH_D              17u
#define SLH_TREE_HEIGHT    4u
#define SLH_FORS_HEIGHT    9u
#define SLH_FORS_TREES     35u
#else
#error "SLH_SECURITY_LEVEL must be 128, 192, or 256"
#endif

#define ADRS_COMPRESSED    22u
#define ADRS_FULL          32u
#define SHA2_ZPAD_LEN      (64u - SLH_N)
#define MODE_SHA2          0u
#define MODE_SHAKE         1u

/* SimpleSerial command sizes are compile-time fixed. */
#define PK_SEED_LEN        SLH_N
#define SHA2_IN_LEN        (ADRS_COMPRESSED + SLH_N)
#define SHAKE_IN_LEN       (ADRS_FULL + SLH_N)
#define MAX_IN_LEN         SHAKE_IN_LEN
#define OUT_LEN            SLH_N
#define SHA256_STATE_SIZE  40u

typedef struct {
    /* Actual SLH-DSA context-style state used by hash/prf_addr code.
     * Only fields needed for FORS/WOTS+ secret-key PRF experiments are kept.
     */
    uint8_t sk_seed[SLH_N];
    uint8_t sk_prf[SLH_N];
    uint8_t pk_seed[SLH_N];
    uint8_t pub_seed[SLH_N];
    uint8_t state_seeded[SHA256_STATE_SIZE];
} spx_ctx;

static spx_ctx ctx;
static uint8_t mode = MODE_SHA2;
static uint8_t current_addr[ADRS_FULL];
static uint8_t out_buf[OUT_LEN];
static uint8_t sha256_state[SHA256_STATE_SIZE];

/* -------------------------------------------------------------------------
 * Utility: big-endian load/store
 * ------------------------------------------------------------------------- */
static uint32_t load_bigendian_32(const uint8_t* x) {
    return (uint32_t)(x[3]) |
        (((uint32_t)x[2]) << 8) |
        (((uint32_t)x[1]) << 16) |
        (((uint32_t)x[0]) << 24);
}

static uint64_t load_bigendian_64(const uint8_t* x) {
    return (uint64_t)(x[7]) |
        (((uint64_t)x[6]) << 8) |
        (((uint64_t)x[5]) << 16) |
        (((uint64_t)x[4]) << 24) |
        (((uint64_t)x[3]) << 32) |
        (((uint64_t)x[2]) << 40) |
        (((uint64_t)x[1]) << 48) |
        (((uint64_t)x[0]) << 56);
}

static void store_bigendian_32(uint8_t* x, uint32_t u) {
    x[3] = (uint8_t)u; u >>= 8;
    x[2] = (uint8_t)u; u >>= 8;
    x[1] = (uint8_t)u; u >>= 8;
    x[0] = (uint8_t)u;
}

/* -------------------------------------------------------------------------
 * SHA-256 core. Trigger is placed around the first message-schedule expansion,
 * matching the original SPHINCS+ v3.0 experiment style.
 * ------------------------------------------------------------------------- */
#define SHR(x, c)      ((x) >> (c))
#define ROTR_32(x, c)  (((x) >> (c)) | ((x) << (32 - (c))))

#define Ch(x, y, z)    (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z)   (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define Sigma0_32(x)   (ROTR_32((x), 2) ^ ROTR_32((x),13) ^ ROTR_32((x),22))
#define Sigma1_32(x)   (ROTR_32((x), 6) ^ ROTR_32((x),11) ^ ROTR_32((x),25))
#define sigma0_32(x)   (ROTR_32((x), 7) ^ ROTR_32((x),18) ^ SHR((x), 3))
#define sigma1_32(x)   (ROTR_32((x),17) ^ ROTR_32((x),19) ^ SHR((x),10))

#define M_32(w0, w14, w9, w1) w0 = sigma1_32(w14) + (w9) + sigma0_32(w1) + (w0);

#define EXPAND_32           \
    M_32(w0, w14, w9, w1)   \
    M_32(w1, w15, w10, w2)  \
    M_32(w2, w0, w11, w3)   \
    M_32(w3, w1, w12, w4)   \
    M_32(w4, w2, w13, w5)   \
    M_32(w5, w3, w14, w6)   \
    M_32(w6, w4, w15, w7)   \
    M_32(w7, w5, w0, w8)    \
    M_32(w8, w6, w1, w9)    \
    M_32(w9, w7, w2, w10)   \
    M_32(w10, w8, w3, w11)  \
    M_32(w11, w9, w4, w12)  \
    M_32(w12, w10, w5, w13) \
    M_32(w13, w11, w6, w14) \
    M_32(w14, w12, w7, w15) \
    M_32(w15, w13, w8, w0)

#define F_32(w, k)                                   \
    T1 = h + Sigma1_32(e) + Ch(e, f, g) + (k) + (w); \
    T2 = Sigma0_32(a) + Maj(a, b, c);                \
    h = g;                                           \
    g = f;                                           \
    f = e;                                           \
    e = d + T1;                                      \
    d = c;                                           \
    c = b;                                           \
    b = a;                                           \
    a = T1 + T2;

static size_t crypto_hashblocks_sha256(uint8_t* statebytes,
    const uint8_t* in, size_t inlen) {
    uint32_t state[8];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
    uint32_t T1;
    uint32_t T2;

    a = load_bigendian_32(statebytes + 0);
    state[0] = a;
    b = load_bigendian_32(statebytes + 4);
    state[1] = b;
    c = load_bigendian_32(statebytes + 8);
    state[2] = c;
    d = load_bigendian_32(statebytes + 12);
    state[3] = d;
    e = load_bigendian_32(statebytes + 16);
    state[4] = e;
    f = load_bigendian_32(statebytes + 20);
    state[5] = f;
    g = load_bigendian_32(statebytes + 24);
    state[6] = g;
    h = load_bigendian_32(statebytes + 28);
    state[7] = h;

    while (inlen >= 64) {
        uint32_t w0 = load_bigendian_32(in + 0);
        uint32_t w1 = load_bigendian_32(in + 4);
        uint32_t w2 = load_bigendian_32(in + 8);
        uint32_t w3 = load_bigendian_32(in + 12);
        uint32_t w4 = load_bigendian_32(in + 16);
        uint32_t w5 = load_bigendian_32(in + 20);
        uint32_t w6 = load_bigendian_32(in + 24);
        uint32_t w7 = load_bigendian_32(in + 28);
        uint32_t w8 = load_bigendian_32(in + 32);
        uint32_t w9 = load_bigendian_32(in + 36);
        uint32_t w10 = load_bigendian_32(in + 40);
        uint32_t w11 = load_bigendian_32(in + 44);
        uint32_t w12 = load_bigendian_32(in + 48);
        uint32_t w13 = load_bigendian_32(in + 52);
        uint32_t w14 = load_bigendian_32(in + 56);
        uint32_t w15 = load_bigendian_32(in + 60);

        trigger_high();
        F_32(w0, 0x428a2f98)
        F_32(w1, 0x71374491)
        F_32(w2, 0xb5c0fbcf)
        F_32(w3, 0xe9b5dba5)
        F_32(w4, 0x3956c25b)
        F_32(w5, 0x59f111f1)
        F_32(w6, 0x923f82a4)
        F_32(w7, 0xab1c5ed5)
        F_32(w8, 0xd807aa98)
        F_32(w9, 0x12835b01)
        F_32(w10, 0x243185be)
        F_32(w11, 0x550c7dc3)
            //trigger_high();
        F_32(w12, 0x72be5d74)
            //trigger_low();
        F_32(w13, 0x80deb1fe)
        F_32(w14, 0x9bdc06a7)
        F_32(w15, 0xc19bf174)
        //trigger_low();

        //trigger_high();
        EXPAND_32
        //trigger_low();

        F_32(w0, 0xe49b69c1)
        F_32(w1, 0xefbe4786)
        F_32(w2, 0x0fc19dc6)
        F_32(w3, 0x240ca1cc)
        F_32(w4, 0x2de92c6f)
        F_32(w5, 0x4a7484aa)
        F_32(w6, 0x5cb0a9dc)
        F_32(w7, 0x76f988da)
        F_32(w8, 0x983e5152)
        F_32(w9, 0xa831c66d)
        F_32(w10, 0xb00327c8)
        F_32(w11, 0xbf597fc7)
        F_32(w12, 0xc6e00bf3)
        F_32(w13, 0xd5a79147)
        F_32(w14, 0x06ca6351)
        F_32(w15, 0x14292967)

        EXPAND_32
        //trigger_low();

        F_32(w0, 0x27b70a85)
        F_32(w1, 0x2e1b2138)
        F_32(w2, 0x4d2c6dfc)
        F_32(w3, 0x53380d13)
        F_32(w4, 0x650a7354)
        F_32(w5, 0x766a0abb)
        F_32(w6, 0x81c2c92e)
        F_32(w7, 0x92722c85)
        F_32(w8, 0xa2bfe8a1)
        F_32(w9, 0xa81a664b)
        F_32(w10, 0xc24b8b70)
        F_32(w11, 0xc76c51a3)
        F_32(w12, 0xd192e819)
        F_32(w13, 0xd6990624)
        F_32(w14, 0xf40e3585)
        F_32(w15, 0x106aa070)

        EXPAND_32

        F_32(w0, 0x19a4c116)
        F_32(w1, 0x1e376c08)
        F_32(w2, 0x2748774c)
        F_32(w3, 0x34b0bcb5)
        F_32(w4, 0x391c0cb3)
        F_32(w5, 0x4ed8aa4a)
        F_32(w6, 0x5b9cca4f)
        F_32(w7, 0x682e6ff3)
        F_32(w8, 0x748f82ee)
        F_32(w9, 0x78a5636f)
        F_32(w10, 0x84c87814)
        F_32(w11, 0x8cc70208)
        F_32(w12, 0x90befffa)
        F_32(w13, 0xa4506ceb)
        F_32(w14, 0xbef9a3f7)
        F_32(w15, 0xc67178f2)
        trigger_low();
        a += state[0];
        b += state[1];
        c += state[2];
        d += state[3];
        e += state[4];
        f += state[5];
        g += state[6];
        h += state[7];

        state[0] = a;
        state[1] = b;
        state[2] = c;
        state[3] = d;
        state[4] = e;
        state[5] = f;
        state[6] = g;
        state[7] = h;

        in += 64;
        inlen -= 64;
    }

    store_bigendian_32(statebytes + 0, state[0]);
    store_bigendian_32(statebytes + 4, state[1]);
    store_bigendian_32(statebytes + 8, state[2]);
    store_bigendian_32(statebytes + 12, state[3]);
    store_bigendian_32(statebytes + 16, state[4]);
    store_bigendian_32(statebytes + 20, state[5]);
    store_bigendian_32(statebytes + 24, state[6]);
    store_bigendian_32(statebytes + 28, state[7]);

    return inlen;
}

static void sha256_inc_finalize(uint8_t* out, uint8_t* state, const uint8_t* in, size_t inlen) {
    uint8_t padded[128];
    uint64_t bytes = load_bigendian_64(state + 32) + inlen;

    crypto_hashblocks_sha256(state, in, inlen);
    in += inlen;
    inlen &= 63;
    in -= inlen;

    for (size_t i = 0; i < inlen; ++i) {
        padded[i] = in[i];
    }
    padded[inlen] = 0x80;

    if (inlen < 56) {
        memset(padded + inlen + 1, 0, 56 - inlen - 1);
        padded[56] = (uint8_t)(bytes >> 53);
        padded[57] = (uint8_t)(bytes >> 45);
        padded[58] = (uint8_t)(bytes >> 37);
        padded[59] = (uint8_t)(bytes >> 29);
        padded[60] = (uint8_t)(bytes >> 21);
        padded[61] = (uint8_t)(bytes >> 13);
        padded[62] = (uint8_t)(bytes >> 5);
        padded[63] = (uint8_t)(bytes << 3);
        crypto_hashblocks_sha256(state, padded, 64);
    } else {
        memset(padded + inlen + 1, 0, 120 - inlen - 1);
        padded[120] = (uint8_t)(bytes >> 53);
        padded[121] = (uint8_t)(bytes >> 45);
        padded[122] = (uint8_t)(bytes >> 37);
        padded[123] = (uint8_t)(bytes >> 29);
        padded[124] = (uint8_t)(bytes >> 21);
        padded[125] = (uint8_t)(bytes >> 13);
        padded[126] = (uint8_t)(bytes >> 5);
        padded[127] = (uint8_t)(bytes << 3);
        crypto_hashblocks_sha256(state, padded, 128);
    }
    memcpy(out, state, 32);
}


/* -------------------------------------------------------------------------
 * SHA-256 incremental context helpers for SLH-DSA SHA2 state_seeded.
 *
 * FIPS205 SHA2 PRF precomputes:
 *     state_seeded = SHA-256 midstate after
 *                    PK.seed || zero[64 - n]
 *
 * For every supported parameter set the precomputed block is exactly 64 bytes:
 *     PK.seed || zero[64-n]
 *
 * Then prf_addr() copies ctx->state_seeded and finalizes with:
 *     ADRS^c || SK.seed    = 22 + n bytes
 * ------------------------------------------------------------------------- */
static void store_bigendian_64(uint8_t* x, uint64_t u) {
    x[7] = (uint8_t)u; u >>= 8;
    x[6] = (uint8_t)u; u >>= 8;
    x[5] = (uint8_t)u; u >>= 8;
    x[4] = (uint8_t)u; u >>= 8;
    x[3] = (uint8_t)u; u >>= 8;
    x[2] = (uint8_t)u; u >>= 8;
    x[1] = (uint8_t)u; u >>= 8;
    x[0] = (uint8_t)u;
}

static void sha256_inc_init(uint8_t state[SHA256_STATE_SIZE]) {
    static const uint8_t iv[32] = {
        0x6a, 0x09, 0xe6, 0x67,
        0xbb, 0x67, 0xae, 0x85,
        0x3c, 0x6e, 0xf3, 0x72,
        0xa5, 0x4f, 0xf5, 0x3a,
        0x51, 0x0e, 0x52, 0x7f,
        0x9b, 0x05, 0x68, 0x8c,
        0x1f, 0x83, 0xd9, 0xab,
        0x5b, 0xe0, 0xcd, 0x19
    };

    memcpy(state, iv, 32);
    memset(state + 32, 0, 8);
}

static void sha256_inc_blocks(uint8_t state[SHA256_STATE_SIZE],
                              const uint8_t* in,
                              size_t inblocks) {
    uint64_t bytes = load_bigendian_64(state + 32);
    size_t inlen = 64u * inblocks;

    crypto_hashblocks_sha256(state, in, inlen);

    bytes += (uint64_t)inlen;
    store_bigendian_64(state + 32, bytes);
}

static void initialize_hash_function(spx_ctx* c) {
    uint8_t block[64];

    memset(block, 0, sizeof(block));

    /* In SLH-DSA, this field is usually called PK.seed or pub_seed.
     * This firmware stores both ctx.pk_seed and ctx.pub_seed for compatibility.
     */
    memcpy(block, c->pub_seed, SLH_N);

    sha256_inc_init(c->state_seeded);
    sha256_inc_blocks(c->state_seeded, block, 1);
}

/* -------------------------------------------------------------------------
 * Keccak/SHAKE256 minimal implementation. Trigger is placed around Keccak-f.
 * ------------------------------------------------------------------------- */
#define ROL64(a, offset) ((((uint64_t)a) << (offset)) ^ (((uint64_t)a) >> (64 - (offset))))
static uint64_t load64_le(const uint8_t *x) {
    uint64_t r = 0;
    for (unsigned i = 0; i < 8; i++) r |= ((uint64_t)x[i]) << (8 * i);
    return r;
}
static void store64_le(uint8_t *x, uint64_t u) {
    for (unsigned i = 0; i < 8; i++) x[i] = (uint8_t)(u >> (8 * i));
}
static const uint64_t KeccakF_RoundConstants[24] = {
    0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
    0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
    0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
    0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
    0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
    0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL
};

static void KeccakF1600_StatePermute(uint64_t *state) {
    unsigned round;
    uint64_t Aba,Abe,Abi,Abo,Abu,Aga,Age,Agi,Ago,Agu,Aka,Ake,Aki,Ako,Aku,Ama,Ame,Ami,Amo,Amu,Asa,Ase,Asi,Aso,Asu;
    uint64_t BCa,BCe,BCi,BCo,BCu,Da,De,Di,Do,Du,Eba,Ebe,Ebi,Ebo,Ebu,Ega,Ege,Egi,Ego,Egu,Eka,Eke,Eki,Eko,Eku,Ema,Eme,Emi,Emo,Emu,Esa,Ese,Esi,Eso,Esu;

    Aba=state[0]; Abe=state[1]; Abi=state[2]; Abo=state[3]; Abu=state[4];
    Aga=state[5]; Age=state[6]; Agi=state[7]; Ago=state[8]; Agu=state[9];
    Aka=state[10]; Ake=state[11]; Aki=state[12]; Ako=state[13]; Aku=state[14];
    Ama=state[15]; Ame=state[16]; Ami=state[17]; Amo=state[18]; Amu=state[19];
    Asa=state[20]; Ase=state[21]; Asi=state[22]; Aso=state[23]; Asu=state[24];

    trigger_high();
    for(round = 0; round < 24; round += 2) {
        BCa = Aba^Aga^Aka^Ama^Asa; BCe = Abe^Age^Ake^Ame^Ase; BCi = Abi^Agi^Aki^Ami^Asi; BCo = Abo^Ago^Ako^Amo^Aso; BCu = Abu^Agu^Aku^Amu^Asu;
        Da = BCu^ROL64(BCe, 1); De = BCa^ROL64(BCi, 1); Di = BCe^ROL64(BCo, 1); Do = BCi^ROL64(BCu, 1); Du = BCo^ROL64(BCa, 1);
        Aba^=Da; BCa=Aba; Age^=De; BCe=ROL64(Age,44); Aki^=Di; BCi=ROL64(Aki,43); Amo^=Do; BCo=ROL64(Amo,21); Asu^=Du; BCu=ROL64(Asu,14);
        Eba=BCa ^((~BCe)&BCi); Eba^=KeccakF_RoundConstants[round]; Ebe=BCe^((~BCi)&BCo); Ebi=BCi^((~BCo)&BCu); Ebo=BCo^((~BCu)&BCa); Ebu=BCu^((~BCa)&BCe);
        Abo^=Do; BCa=ROL64(Abo,28); Agu^=Du; BCe=ROL64(Agu,20); Aka^=Da; BCi=ROL64(Aka,3); Ame^=De; BCo=ROL64(Ame,45); Asi^=Di; BCu=ROL64(Asi,61);
        Ega=BCa^((~BCe)&BCi); Ege=BCe^((~BCi)&BCo); Egi=BCi^((~BCo)&BCu); Ego=BCo^((~BCu)&BCa); Egu=BCu^((~BCa)&BCe);
        Abe^=De; BCa=ROL64(Abe,1); Agi^=Di; BCe=ROL64(Agi,6); Ako^=Do; BCi=ROL64(Ako,25); Amu^=Du; BCo=ROL64(Amu,8); Asa^=Da; BCu=ROL64(Asa,18);
        Eka=BCa^((~BCe)&BCi); Eke=BCe^((~BCi)&BCo); Eki=BCi^((~BCo)&BCu); Eko=BCo^((~BCu)&BCa); Eku=BCu^((~BCa)&BCe);
        Abu^=Du; BCa=ROL64(Abu,27); Aga^=Da; BCe=ROL64(Aga,36); Ake^=De; BCi=ROL64(Ake,10); Ami^=Di; BCo=ROL64(Ami,15); Aso^=Do; BCu=ROL64(Aso,56);
        Ema=BCa^((~BCe)&BCi); Eme=BCe^((~BCi)&BCo); Emi=BCi^((~BCo)&BCu); Emo=BCo^((~BCu)&BCa); Emu=BCu^((~BCa)&BCe);
        Abi^=Di; BCa=ROL64(Abi,62); Ago^=Do; BCe=ROL64(Ago,55); Aku^=Du; BCi=ROL64(Aku,39); Ama^=Da; BCo=ROL64(Ama,41); Ase^=De; BCu=ROL64(Ase,2);
        Esa=BCa^((~BCe)&BCi); Ese=BCe^((~BCi)&BCo); Esi=BCi^((~BCo)&BCu); Eso=BCo^((~BCu)&BCa); Esu=BCu^((~BCa)&BCe);
        BCa=Eba^Ega^Eka^Ema^Esa; BCe=Ebe^Ege^Eke^Eme^Ese; BCi=Ebi^Egi^Eki^Emi^Esi; BCo=Ebo^Ego^Eko^Emo^Eso; BCu=Ebu^Egu^Eku^Emu^Esu;
        Da=BCu^ROL64(BCe,1); De=BCa^ROL64(BCi,1); Di=BCe^ROL64(BCo,1); Do=BCi^ROL64(BCu,1); Du=BCo^ROL64(BCa,1);
        Eba^=Da; BCa=Eba; Ege^=De; BCe=ROL64(Ege,44); Eki^=Di; BCi=ROL64(Eki,43); Emo^=Do; BCo=ROL64(Emo,21); Esu^=Du; BCu=ROL64(Esu,14);
        Aba=BCa^((~BCe)&BCi); Aba^=KeccakF_RoundConstants[round+1]; Abe=BCe^((~BCi)&BCo); Abi=BCi^((~BCo)&BCu); Abo=BCo^((~BCu)&BCa); Abu=BCu^((~BCa)&BCe);
        Ebo^=Do; BCa=ROL64(Ebo,28); Egu^=Du; BCe=ROL64(Egu,20); Eka^=Da; BCi=ROL64(Eka,3); Eme^=De; BCo=ROL64(Eme,45); Esi^=Di; BCu=ROL64(Esi,61);
        Aga=BCa^((~BCe)&BCi); Age=BCe^((~BCi)&BCo); Agi=BCi^((~BCo)&BCu); Ago=BCo^((~BCu)&BCa); Agu=BCu^((~BCa)&BCe);
        Ebe^=De; BCa=ROL64(Ebe,1); Egi^=Di; BCe=ROL64(Egi,6); Eko^=Do; BCi=ROL64(Eko,25); Emu^=Du; BCo=ROL64(Emu,8); Esa^=Da; BCu=ROL64(Esa,18);
        Aka=BCa^((~BCe)&BCi); Ake=BCe^((~BCi)&BCo); Aki=BCi^((~BCo)&BCu); Ako=BCo^((~BCu)&BCa); Aku=BCu^((~BCa)&BCe);
        Ebu^=Du; BCa=ROL64(Ebu,27); Ega^=Da; BCe=ROL64(Ega,36); Eke^=De; BCi=ROL64(Eke,10); Emi^=Di; BCo=ROL64(Emi,15); Eso^=Do; BCu=ROL64(Eso,56);
        Ama=BCa^((~BCe)&BCi); Ame=BCe^((~BCi)&BCo); Ami=BCi^((~BCo)&BCu); Amo=BCo^((~BCu)&BCa); Amu=BCu^((~BCa)&BCe);
        Ebi^=Di; BCa=ROL64(Ebi,62); Ego^=Do; BCe=ROL64(Ego,55); Eku^=Du; BCi=ROL64(Eku,39); Ema^=Da; BCo=ROL64(Ema,41); Ese^=De; BCu=ROL64(Ese,2);
        Asa=BCa^((~BCe)&BCi); Ase=BCe^((~BCi)&BCo); Asi=BCi^((~BCo)&BCu); Aso=BCo^((~BCu)&BCa); Asu=BCu^((~BCa)&BCe);
    }
    trigger_low();
    state[0]=Aba; state[1]=Abe; state[2]=Abi; state[3]=Abo; state[4]=Abu;
    state[5]=Aga; state[6]=Age; state[7]=Agi; state[8]=Ago; state[9]=Agu;
    state[10]=Aka; state[11]=Ake; state[12]=Aki; state[13]=Ako; state[14]=Aku;
    state[15]=Ama; state[16]=Ame; state[17]=Ami; state[18]=Amo; state[19]=Amu;
    state[20]=Asa; state[21]=Ase; state[22]=Asi; state[23]=Aso; state[24]=Asu;
}

static void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    uint64_t s[25];
    uint8_t t[136];
    const size_t rate = 136; /* SHAKE256 rate = 1088 bits */
    memset(s, 0, sizeof(s));

    while (inlen >= rate) {
        for (size_t i = 0; i < rate / 8; i++) s[i] ^= load64_le(in + 8 * i);
        KeccakF1600_StatePermute(s);
        in += rate;
        inlen -= rate;
    }

    memset(t, 0, rate);
    memcpy(t, in, inlen);
    t[inlen] = 0x1F;       /* SHAKE domain separator */
    t[rate - 1] |= 0x80;
    for (size_t i = 0; i < rate / 8; i++) s[i] ^= load64_le(t + 8 * i);
    KeccakF1600_StatePermute(s);

    while (outlen > 0) {
        size_t block = outlen < rate ? outlen : rate;
        for (size_t i = 0; i < rate / 8; i++) store64_le(t + 8 * i, s[i]);
        memcpy(out, t, block);
        out += block;
        outlen -= block;
        if (outlen > 0) KeccakF1600_StatePermute(s);
    }
}

/* -------------------------------------------------------------------------
 * SLH-DSA PRF wrappers
 * ------------------------------------------------------------------------- */
static void compress_address_sha2(uint8_t out[ADRS_COMPRESSED], const uint8_t addr[ADRS_FULL]) {
    /* SHA2 uses ADRS^c. For the FIPS205 reference layout, the compressed
     * 22-byte address is the first 22 bytes of the byte address representation.
     * The Python capture code should build WOTS_PRF type=5 and FORS_PRF type=6
     * addresses in the same byte-address format.
     */
    memcpy(out, addr, ADRS_COMPRESSED);
}

static void prf_addr_sha2(uint8_t out[OUT_LEN], const spx_ctx *c, const uint8_t addr[ADRS_FULL]) {
    uint8_t digest[32];
    uint8_t addr_c[ADRS_COMPRESSED];
    uint8_t buf[ADRS_COMPRESSED + SLH_N];

    compress_address_sha2(addr_c, addr);

    /* FIPS205 hash_sha2.c prf_addr():
     *   sha2_state = ctx->state_seeded
     *   buf = ADRS^c || SK.seed
     *   sha256_inc_finalize(outbuf, sha2_state, buf, 22 + n)
     */
    memcpy(sha256_state, c->state_seeded, SHA256_STATE_SIZE);
    memcpy(buf, addr_c, ADRS_COMPRESSED);
    memcpy(buf + ADRS_COMPRESSED, c->sk_seed, SLH_N);
    sha256_inc_finalize(digest, sha256_state, buf, ADRS_COMPRESSED + SLH_N);
    memcpy(out, digest, OUT_LEN);
}

static void prf_addr_shake(uint8_t out[OUT_LEN], const spx_ctx *c, const uint8_t addr[ADRS_FULL]) {
    uint8_t msg[SLH_N + ADRS_FULL + SLH_N];
    size_t off = 0;

    /* FIPS205 SHAKE PRF input: PK.seed || ADRS || SK.seed */
    memcpy(msg + off, c->pub_seed, SLH_N); off += SLH_N;
    memcpy(msg + off, addr, ADRS_FULL); off += ADRS_FULL;
    memcpy(msg + off, c->sk_seed, SLH_N); off += SLH_N;
    shake256(out, OUT_LEN, msg, off);
}

static void slh_dsa_prf_addr(uint8_t out[OUT_LEN], const spx_ctx *c, const uint8_t addr[ADRS_FULL]) {
    if (mode == MODE_SHA2) {
        prf_addr_sha2(out, c, addr);
    } else {
        prf_addr_shake(out, c, addr);
    }
}

/* -------------------------------------------------------------------------
 * SimpleSerial commands
 * ------------------------------------------------------------------------- */
static uint8_t cmd_set_mode(uint8_t* data, uint8_t len) {
    if (len != 1) return 0x01;
    if (data[0] != MODE_SHA2 && data[0] != MODE_SHAKE) return 0x02;
    mode = data[0];
    return 0x00;
}

static uint8_t cmd_set_pk_seed(uint8_t* data, uint8_t len) {
    if (len != SLH_N) return 0x01;
    memcpy(ctx.pk_seed, data, SLH_N);
    memcpy(ctx.pub_seed, data, SLH_N);
    initialize_hash_function(&ctx);
    return 0x00;
}

static uint8_t cmd_set_sk_seed(uint8_t* data, uint8_t len) {
    if (len != SLH_N) return 0x01;
    memcpy(ctx.sk_seed, data, SLH_N);
    return 0x00;
}

static uint8_t cmd_set_sk_prf(uint8_t* data, uint8_t len) {
    if (len != SLH_N) return 0x01;
    memcpy(ctx.sk_prf, data, SLH_N);
    return 0x00;
}

/* A command payload is always the full 32-byte ADRS.
 * WOTS+ PRF address should have type=5 and hash address=0.
 * FORS PRF address should have type=6 and tree height=0.
 * Those fields are set by the Python capture-side address builder.
 */
static uint8_t cmd_set_addr(uint8_t* data, uint8_t len) {
    if (len != ADRS_FULL) return 0x01;
    memcpy(current_addr, data, ADRS_FULL);
    return 0x00;
}

static uint8_t cmd_read_addr(uint8_t* data, uint8_t len) {
    (void)data; (void)len;
    simpleserial_put('r', ADRS_FULL, current_addr);
    return 0x00;
}

static uint8_t cmd_read_mode(uint8_t* data, uint8_t len) {
    (void)data; (void)len;
    simpleserial_put('r', 1, &mode);
    return 0x00;
}

static uint8_t cmd_read_n(uint8_t* data, uint8_t len) {
    uint8_t n = (uint8_t)SLH_N;
    (void)data; (void)len;
    simpleserial_put('r', 1, &n);
    return 0x00;
}

static uint8_t cmd_sample(uint8_t* data, uint8_t len) {
    (void)data; (void)len;
    slh_dsa_prf_addr(out_buf, &ctx, current_addr);
    return 0x00;
}

static uint8_t cmd_get_out(uint8_t* data, uint8_t len) {
    (void)data; (void)len;
    simpleserial_put('r', OUT_LEN, out_buf);
    return 0x00;
}

int main(void) {
    platform_init();
    init_uart();
    trigger_setup();
    simpleserial_init();

    memset(&ctx, 0, sizeof(ctx));
    memset(current_addr, 0, sizeof(current_addr));
    memset(out_buf, 0, sizeof(out_buf));
    initialize_hash_function(&ctx);

    simpleserial_addcmd('M', 1, cmd_set_mode);          /* 0=SHA2, 1=SHAKE */
    simpleserial_addcmd('P', SLH_N, cmd_set_pk_seed);   /* PK.seed / pub_seed */
    simpleserial_addcmd('S', SLH_N, cmd_set_sk_seed);   /* SK.seed */
    simpleserial_addcmd('Q', SLH_N, cmd_set_sk_prf);    /* SK.prf, stored for ctx compatibility */
    simpleserial_addcmd('A', ADRS_FULL, cmd_set_addr);  /* ADRS */
    simpleserial_addcmd('R', 0, cmd_read_addr);
    simpleserial_addcmd('B', 0, cmd_read_mode);
    simpleserial_addcmd('N', 0, cmd_read_n);            /* compile-time n: 16/24/32 */
    simpleserial_addcmd('T', 0, cmd_sample);
    simpleserial_addcmd('Z', 0, cmd_get_out);

    while (1) {
        simpleserial_get();
    }
}