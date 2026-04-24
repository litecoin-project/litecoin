// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/crypto/Bulletproofs.h>
#include <secp256k1_bulletproofs.h>
#include <secp256k1_generator.h>

#include <test_framework/TestMWEB.h>

typedef struct {
    uint64_t d[4];
} secp256k1_scalar;


#define SECP256K1_N_0 ((uint64_t)0xBFD25E8CD0364141ULL)
#define SECP256K1_N_1 ((uint64_t)0xBAAEDCE6AF48A03BULL)
#define SECP256K1_N_2 ((uint64_t)0xFFFFFFFFFFFFFFFEULL)
#define SECP256K1_N_3 ((uint64_t)0xFFFFFFFFFFFFFFFFULL)

#ifdef WORDS_BIGENDIAN
#define LE32(p) ((((p) & 0xFF) << 24) | (((p) & 0xFF00) << 8) | (((p) & 0xFF0000) >> 8) | (((p) & 0xFF000000) >> 24))
#define BE32(p) (p)
#else
#define BE32(p) ((((p) & 0xFF) << 24) | (((p) & 0xFF00) << 8) | (((p) & 0xFF0000) >> 8) | (((p) & 0xFF000000) >> 24))
#define LE32(p) (p)
#endif

constexpr static inline uint32_t rotl32(uint32_t v, int c) { return (v << c) | (v >> (32 - c)); }

#define QUARTERROUND(a,b,c,d) \
  a += b; d = rotl32(d ^ a, 16); \
  c += d; b = rotl32(b ^ c, 12); \
  a += b; d = rotl32(d ^ a, 8); \
  c += d; b = rotl32(b ^ c, 7);


static int secp256k1_scalar_check_overflow(const secp256k1_scalar *a) {
    int yes = 0;
    int no = 0;
    no |= (a->d[3] < SECP256K1_N_3); /* No need for a > check. */
    no |= (a->d[2] < SECP256K1_N_2);
    yes |= (a->d[2] > SECP256K1_N_2) & ~no;
    no |= (a->d[1] < SECP256K1_N_1);
    yes |= (a->d[1] > SECP256K1_N_1) & ~no;
    yes |= (a->d[0] >= SECP256K1_N_0) & ~no;
    return yes;
}

static void secp256k1_scalar_chacha20(secp256k1_scalar *r1, secp256k1_scalar *r2, const unsigned char *seed, uint64_t idx) {
    size_t n;
    size_t over_count = 0;
    uint32_t seed32[8];
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
    int over1, over2;

    memcpy((void *) seed32, (const void *) seed, 32);
    do {
        x0 = 0x61707865;
        x1 = 0x3320646e;
        x2 = 0x79622d32;
        x3 = 0x6b206574;
        x4 = LE32(seed32[0]);
        x5 = LE32(seed32[1]);
        x6 = LE32(seed32[2]);
        x7 = LE32(seed32[3]);
        x8 = LE32(seed32[4]);
        x9 = LE32(seed32[5]);
        x10 = LE32(seed32[6]);
        x11 = LE32(seed32[7]);
        x12 = idx;
        x13 = idx >> 32;
        x14 = 0;
        x15 = over_count;

        n = 10;
        while (n--) {
            QUARTERROUND(x0, x4, x8,x12)
            QUARTERROUND(x1, x5, x9,x13)
            QUARTERROUND(x2, x6,x10,x14)
            QUARTERROUND(x3, x7,x11,x15)
            QUARTERROUND(x0, x5,x10,x15)
            QUARTERROUND(x1, x6,x11,x12)
            QUARTERROUND(x2, x7, x8,x13)
            QUARTERROUND(x3, x4, x9,x14)
        }

        x0 += 0x61707865;
        x1 += 0x3320646e;
        x2 += 0x79622d32;
        x3 += 0x6b206574;
        x4 += LE32(seed32[0]);
        x5 += LE32(seed32[1]);
        x6 += LE32(seed32[2]);
        x7 += LE32(seed32[3]);
        x8 += LE32(seed32[4]);
        x9 += LE32(seed32[5]);
        x10 += LE32(seed32[6]);
        x11 += LE32(seed32[7]);
        x12 += idx;
        x13 += idx >> 32;
        x14 += 0;
        x15 += over_count;

        r1->d[3] = BE32((uint64_t) x0) << 32 | BE32(x1);
        r1->d[2] = BE32((uint64_t) x2) << 32 | BE32(x3);
        r1->d[1] = BE32((uint64_t) x4) << 32 | BE32(x5);
        r1->d[0] = BE32((uint64_t) x6) << 32 | BE32(x7);
        r2->d[3] = BE32((uint64_t) x8) << 32 | BE32(x9);
        r2->d[2] = BE32((uint64_t) x10) << 32 | BE32(x11);
        r2->d[1] = BE32((uint64_t) x12) << 32 | BE32(x13);
        r2->d[0] = BE32((uint64_t) x14) << 32 | BE32(x15);

        over1 = secp256k1_scalar_check_overflow(r1);
        over2 = secp256k1_scalar_check_overflow(r2);
        over_count++;
   } while (over1 | over2);
}

static void secp256k1_scalar_get_b32(unsigned char *bin, const secp256k1_scalar* a) {
    bin[0] = a->d[3] >> 56; bin[1] = a->d[3] >> 48; bin[2] = a->d[3] >> 40; bin[3] = a->d[3] >> 32; bin[4] = a->d[3] >> 24; bin[5] = a->d[3] >> 16; bin[6] = a->d[3] >> 8; bin[7] = a->d[3];
    bin[8] = a->d[2] >> 56; bin[9] = a->d[2] >> 48; bin[10] = a->d[2] >> 40; bin[11] = a->d[2] >> 32; bin[12] = a->d[2] >> 24; bin[13] = a->d[2] >> 16; bin[14] = a->d[2] >> 8; bin[15] = a->d[2];
    bin[16] = a->d[1] >> 56; bin[17] = a->d[1] >> 48; bin[18] = a->d[1] >> 40; bin[19] = a->d[1] >> 32; bin[20] = a->d[1] >> 24; bin[21] = a->d[1] >> 16; bin[22] = a->d[1] >> 8; bin[23] = a->d[1];
    bin[24] = a->d[0] >> 56; bin[25] = a->d[0] >> 48; bin[26] = a->d[0] >> 40; bin[27] = a->d[0] >> 32; bin[28] = a->d[0] >> 24; bin[29] = a->d[0] >> 16; bin[30] = a->d[0] >> 8; bin[31] = a->d[0];
}

BOOST_FIXTURE_TEST_SUITE(TestRangeProofs, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(RangeProofs)
{
    const uint64_t value = 12345678;
    BlindingFactor blind = BlindingFactor::FromHex("0000000000000000000000000000000000000000000000000000000000000001");
    Commitment commit = Commitment::Blinded(blind, value);
    SecretKey nonce = SecretKey::FromHex("5021e7378095d5dc0dc59d7886a4f65c126db9580a1dde3fedc4fe6dc7734cd5");
    BigInt<32> message = BigInt<32>::FromHex("c2ca9d0aa93184f598f595147cd6c786f2bafb7000112233445566778899aabb");
    std::vector<uint8_t> extraData = ParseHex("d21cf3d38aa9a7de357949164d8134a7686a7b107c279f50735d487874ffc56fe0b62b759baf6ecde5a73dd6932634f97501");

    secp256k1_scalar alpha;
    secp256k1_scalar rho;
    secp256k1_scalar_chacha20(&alpha, &rho, nonce.data(), 0);

    std::vector<uint8_t> alpha_out(32);
    secp256k1_scalar_get_b32(alpha_out.data(), &alpha);

    std::vector<uint8_t> rho_out(32);
    secp256k1_scalar_get_b32(rho_out.data(), &rho);

    // Create a RangeProof via Bulletproofs::Generate.
    RangeProof::CPtr pRangeProof = Bulletproofs::Generate(
        value,
        SecretKey(blind.vec()),
        nonce,
        message,
        extraData
    );

    // Try rewinding it via Bulletproofs::Rewind using the *correct* rewind nonce.
    BigInt<32> bp_message = Bulletproofs::Rewind(commit, *pRangeProof, extraData, nonce);

    BOOST_CHECK(bp_message == message);

    // Make sure BatchVerify returns true.
    std::vector<ProofData> rangeProofs;
    rangeProofs.push_back(ProofData{ commit, pRangeProof, extraData });
    BOOST_REQUIRE(Bulletproofs::BatchVerify(rangeProofs));
}

BOOST_AUTO_TEST_SUITE_END()
