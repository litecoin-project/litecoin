/***********************************************************************
 * Copyright (c) 2018-2020 Andrew Poelstra, Jonas Nick                 *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORRSIG_MAIN_H
#define SECP256K1_MODULE_SCHNORRSIG_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_schnorrsig.h"
#include "../../hash.h"

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/nonce")||SHA256("BIP0340/nonce"). */
static void secp256k1_nonce_function_bip340_sha256_tagged(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x46615b35ul;
    sha->s[1] = 0xf4bfbff7ul;
    sha->s[2] = 0x9f8dc671ul;
    sha->s[3] = 0x83627ab3ul;
    sha->s[4] = 0x60217180ul;
    sha->s[5] = 0x57358661ul;
    sha->s[6] = 0x21a29e54ul;
    sha->s[7] = 0x68b07b4cul;

    sha->bytes = 64;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/aux")||SHA256("BIP0340/aux"). */
static void secp256k1_nonce_function_bip340_sha256_tagged_aux(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x24dd3219ul;
    sha->s[1] = 0x4eba7e70ul;
    sha->s[2] = 0xca0fabb9ul;
    sha->s[3] = 0x0fa3166dul;
    sha->s[4] = 0x3afbe4b1ul;
    sha->s[5] = 0x4c44df97ul;
    sha->s[6] = 0x4aac2739ul;
    sha->s[7] = 0x249e850aul;

    sha->bytes = 64;
}

/* algo argument for nonce_function_bip340 to derive the nonce exactly as stated in BIP-340
 * by using the correct tagged hash function. */
static const unsigned char bip340_algo[13] = "BIP0340/nonce";

static const unsigned char schnorrsig_extraparams_magic[4] = SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC;

static int nonce_function_bip340(unsigned char *nonce32, const unsigned char *msg, size_t msglen, const unsigned char *key32, const unsigned char *xonly_pk32, const unsigned char *algo, size_t algolen, void *data) {
    secp256k1_sha256 sha;
    unsigned char masked_key[32];
    int i;

    if (algo == NULL) {
        return 0;
    }

    if (data != NULL) {
        secp256k1_nonce_function_bip340_sha256_tagged_aux(&sha);
        secp256k1_sha256_write(&sha, data, 32);
        secp256k1_sha256_finalize(&sha, masked_key);
        for (i = 0; i < 32; i++) {
            masked_key[i] ^= key32[i];
        }
    } else {
        /* Precomputed TaggedHash("BIP0340/aux", 0x0000...00); */
        static const unsigned char ZERO_MASK[32] = {
              84, 241, 105, 207, 201, 226, 229, 114,
             116, 128,  68,  31, 144, 186,  37, 196,
             136, 244,  97, 199,  11,  94, 165, 220,
             170, 247, 175, 105, 39,  10, 165,  20
        };
        for (i = 0; i < 32; i++) {
            masked_key[i] = key32[i] ^ ZERO_MASK[i];
        }
    }

    /* Tag the hash with algo which is important to avoid nonce reuse across
     * algorithms. If this nonce function is used in BIP-340 signing as defined
     * in the spec, an optimized tagging implementation is used. */
    if (algolen == sizeof(bip340_algo)
            && secp256k1_memcmp_var(algo, bip340_algo, algolen) == 0) {
        secp256k1_nonce_function_bip340_sha256_tagged(&sha);
    } else {
        secp256k1_sha256_initialize_tagged(&sha, algo, algolen);
    }

    /* Hash masked-key||pk||msg using the tagged hash as per the spec */
    secp256k1_sha256_write(&sha, masked_key, 32);
    secp256k1_sha256_write(&sha, xonly_pk32, 32);
    secp256k1_sha256_write(&sha, msg, msglen);
    secp256k1_sha256_finalize(&sha, nonce32);
    return 1;
}

const secp256k1_nonce_function_hardened secp256k1_nonce_function_bip340 = nonce_function_bip340;

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/challenge")||SHA256("BIP0340/challenge"). */
static void secp256k1_schnorrsig_sha256_tagged(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x9cecba11ul;
    sha->s[1] = 0x23925381ul;
    sha->s[2] = 0x11679112ul;
    sha->s[3] = 0xd1627e0ful;
    sha->s[4] = 0x97c87550ul;
    sha->s[5] = 0x003cc765ul;
    sha->s[6] = 0x90f61164ul;
    sha->s[7] = 0x33e9b66aul;
    sha->bytes = 64;
}

static void secp256k1_schnorrsig_challenge(secp256k1_scalar* e, const unsigned char *r32, const unsigned char *msg, size_t msglen, const unsigned char *pubkey32)
{
    unsigned char buf[32];
    secp256k1_sha256 sha;

    /* tagged hash(r.x, pk.x, msg) */
    secp256k1_schnorrsig_sha256_tagged(&sha);
    secp256k1_sha256_write(&sha, r32, 32);
    secp256k1_sha256_write(&sha, pubkey32, 32);
    secp256k1_sha256_write(&sha, msg, msglen);
    secp256k1_sha256_finalize(&sha, buf);
    /* Set scalar e to the challenge hash modulo the curve order as per
     * BIP340. */
    secp256k1_scalar_set_b32(e, buf, NULL);
}

static int secp256k1_schnorrsig_sign_internal(const secp256k1_context* ctx, unsigned char *sig64, const unsigned char *msg, size_t msglen, const secp256k1_keypair *keypair, secp256k1_nonce_function_hardened noncefp, void *ndata) {
    secp256k1_scalar sk;
    secp256k1_scalar e;
    secp256k1_scalar k;
    secp256k1_gej rj;
    secp256k1_ge pk;
    secp256k1_ge r;
    unsigned char buf[32] = { 0 };
    unsigned char pk_buf[32];
    unsigned char seckey[32];
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg != NULL || msglen == 0);
    ARG_CHECK(keypair != NULL);

    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_bip340;
    }

    ret &= secp256k1_keypair_load(ctx, &sk, &pk, keypair);
    /* Because we are signing for a x-only pubkey, the secret key is negated
     * before signing if the point corresponding to the secret key does not
     * have an even Y. */
    if (secp256k1_fe_is_odd(&pk.y)) {
        secp256k1_scalar_negate(&sk, &sk);
    }

    secp256k1_scalar_get_b32(seckey, &sk);
    secp256k1_fe_get_b32(pk_buf, &pk.x);
    ret &= !!noncefp(buf, msg, msglen, seckey, pk_buf, bip340_algo, sizeof(bip340_algo), ndata);
    secp256k1_scalar_set_b32(&k, buf, NULL);
    ret &= !secp256k1_scalar_is_zero(&k);
    secp256k1_scalar_cmov(&k, &secp256k1_scalar_one, !ret);

    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &k);
    secp256k1_ge_set_gej(&r, &rj);

    /* We declassify r to allow using it as a branch point. This is fine
     * because r is not a secret. */
    secp256k1_declassify(ctx, &r, sizeof(r));
    secp256k1_fe_normalize_var(&r.y);
    if (secp256k1_fe_is_odd(&r.y)) {
        secp256k1_scalar_negate(&k, &k);
    }
    secp256k1_fe_normalize_var(&r.x);
    secp256k1_fe_get_b32(&sig64[0], &r.x);

    secp256k1_schnorrsig_challenge(&e, &sig64[0], msg, msglen, pk_buf);
    secp256k1_scalar_mul(&e, &e, &sk);
    secp256k1_scalar_add(&e, &e, &k);
    secp256k1_scalar_get_b32(&sig64[32], &e);

    secp256k1_memczero(sig64, 64, !ret);
    secp256k1_scalar_clear(&k);
    secp256k1_scalar_clear(&sk);
    memset(seckey, 0, sizeof(seckey));

    return ret;
}

int secp256k1_schnorrsig_sign32(const secp256k1_context* ctx, unsigned char *sig64, const unsigned char *msg32, const secp256k1_keypair *keypair, const unsigned char *aux_rand32) {
    /* We cast away const from the passed aux_rand32 argument since we know the default nonce function does not modify it. */
    return secp256k1_schnorrsig_sign_internal(ctx, sig64, msg32, 32, keypair, secp256k1_nonce_function_bip340, (unsigned char*)aux_rand32);
}

int secp256k1_schnorrsig_sign(const secp256k1_context* ctx, unsigned char* sig64, const unsigned char* msg32, const secp256k1_keypair* keypair, const unsigned char* aux_rand32)
{
    return secp256k1_schnorrsig_sign32(ctx, sig64, msg32, keypair, aux_rand32);
}

int secp256k1_schnorrsig_sign_custom(const secp256k1_context* ctx, unsigned char *sig64, const unsigned char *msg, size_t msglen, const secp256k1_keypair *keypair, secp256k1_schnorrsig_extraparams *extraparams) {
    secp256k1_nonce_function_hardened noncefp = NULL;
    void *ndata = NULL;
    VERIFY_CHECK(ctx != NULL);

    if (extraparams != NULL) {
        ARG_CHECK(secp256k1_memcmp_var(extraparams->magic,
                                       schnorrsig_extraparams_magic,
                                       sizeof(extraparams->magic)) == 0);
        noncefp = extraparams->noncefp;
        ndata = extraparams->ndata;
    }
    return secp256k1_schnorrsig_sign_internal(ctx, sig64, msg, msglen, keypair, noncefp, ndata);
}

/* This nonce function is described in BIP-schnorr
 * (https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki) */
static int secp256k1_nonce_function_bipschnorr(unsigned char* nonce32, const unsigned char* msg32, const unsigned char* key32, const unsigned char* algo16, void* data, unsigned int counter)
{
    secp256k1_sha256 sha;
    (void)data;
    (void)counter;
    VERIFY_CHECK(counter == 0);

    /* Hash x||msg as per the spec */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, key32, 32);
    secp256k1_sha256_write(&sha, msg32, 32);
    /* Hash in algorithm, which is not in the spec, but may be critical to
	 * users depending on it to avoid nonce reuse across algorithms. */
    if (algo16 != NULL) {
        secp256k1_sha256_write(&sha, algo16, 16);
    }
    secp256k1_sha256_finalize(&sha, nonce32);
    return 1;
}

int secp256k1_schnorrsig_sign_mweb(const secp256k1_context* ctx, unsigned char* sig, int* nonce_is_negated, const unsigned char* msg32, const unsigned char* seckey, secp256k1_nonce_function noncefp, void* ndata)
{
    secp256k1_scalar x;
    secp256k1_scalar e;
    secp256k1_scalar k;
    secp256k1_gej pkj;
    secp256k1_gej rj;
    secp256k1_ge pk;
    secp256k1_ge r;
    secp256k1_sha256 sha;
    int overflow;
    unsigned char buf[33];
    size_t buflen = sizeof(buf);

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(sig != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(seckey != NULL);

    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_bipschnorr;
    }
    secp256k1_scalar_set_b32(&x, seckey, &overflow);
    /* Fail if the secret key is invalid. */
    if (overflow || secp256k1_scalar_is_zero(&x)) {
        memset(sig, 0, sizeof(*sig));
        return 0;
    }

    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pkj, &x);
    secp256k1_ge_set_gej(&pk, &pkj);

    if (!noncefp(buf, msg32, seckey, NULL, (void*)ndata, 0)) {
        return 0;
    }
    secp256k1_scalar_set_b32(&k, buf, NULL);
    if (secp256k1_scalar_is_zero(&k)) {
        return 0;
    }

    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &k);
    secp256k1_ge_set_gej(&r, &rj);

    if (nonce_is_negated != NULL) {
        *nonce_is_negated = 0;
    }
    if (!secp256k1_fe_is_quad_var(&r.y)) {
        secp256k1_scalar_negate(&k, &k);
        if (nonce_is_negated != NULL) {
            *nonce_is_negated = 1;
        }
    }
    secp256k1_fe_normalize(&r.x);
    secp256k1_fe_get_b32(&sig[0], &r.x);

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, &sig[0], 32);
    secp256k1_eckey_pubkey_serialize(&pk, buf, &buflen, 1);
    secp256k1_sha256_write(&sha, buf, buflen);
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_sha256_finalize(&sha, buf);

    secp256k1_scalar_set_b32(&e, buf, NULL);
    secp256k1_scalar_mul(&e, &e, &x);
    secp256k1_scalar_add(&e, &e, &k);

    secp256k1_scalar_get_b32(&sig[32], &e);
    secp256k1_scalar_clear(&k);
    secp256k1_scalar_clear(&x);

    return 1;
}

int secp256k1_schnorrsig_verify(const secp256k1_context* ctx, const unsigned char *sig64, const unsigned char *msg, size_t msglen, const secp256k1_xonly_pubkey *pubkey) {
    secp256k1_scalar s;
    secp256k1_scalar e;
    secp256k1_gej rj;
    secp256k1_ge pk;
    secp256k1_gej pkj;
    secp256k1_fe rx;
    secp256k1_ge r;
    unsigned char buf[32];
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg != NULL || msglen == 0);
    ARG_CHECK(pubkey != NULL);

    if (!secp256k1_fe_set_b32(&rx, &sig64[0])) {
        return 0;
    }

    secp256k1_scalar_set_b32(&s, &sig64[32], &overflow);
    if (overflow) {
        return 0;
    }

    if (!secp256k1_xonly_pubkey_load(ctx, &pk, pubkey)) {
        return 0;
    }

    /* Compute e. */
    secp256k1_fe_get_b32(buf, &pk.x);
    secp256k1_schnorrsig_challenge(&e, &sig64[0], msg, msglen, buf);

    /* Compute rj =  s*G + (-e)*pkj */
    secp256k1_scalar_negate(&e, &e);
    secp256k1_gej_set_ge(&pkj, &pk);
    secp256k1_ecmult(&rj, &pkj, &e, &s);

    secp256k1_ge_set_gej_var(&r, &rj);
    if (secp256k1_ge_is_infinity(&r)) {
        return 0;
    }

    secp256k1_fe_normalize_var(&r.y);
    return !secp256k1_fe_is_odd(&r.y) &&
           secp256k1_fe_equal_var(&rx, &r.x);
}

/* Data that is used by the batch verification ecmult callback */
typedef struct {
    const secp256k1_context *ctx;
    /* Seed for the random number generator */
    unsigned char chacha_seed[32];
    /* Caches randomizers generated by the PRNG which returns two randomizers per call. Caching
     * avoids having to call the PRNG twice as often. The very first randomizer will be set to 1 and
     * the PRNG is called at every odd indexed schnorrsig to fill the cache. */
    secp256k1_scalar randomizer_cache[2];
    /* Signature, message, public key tuples to verify */
    const uint8_t *const *sig;
    const unsigned char *const *msg32;
    const secp256k1_pubkey *const *pk;
    size_t n_sigs;
} secp256k1_schnorrsig_verify_ecmult_context;

/* Callback function which is called by ecmult_multi in order to convert the ecmult_context
 * consisting of signature, message and public key tuples into scalars and points. */
static int secp256k1_schnorrsig_verify_batch_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_schnorrsig_verify_ecmult_context *ecmult_context = (secp256k1_schnorrsig_verify_ecmult_context *) data;

    if (idx % 4 == 2) {
        /* Every idx corresponds to a (scalar,point)-tuple. So this callback is called with 4
         * consecutive tuples before we need to call the RNG for new randomizers:
         * (-randomizer_cache[0], R1)
         * (-randomizer_cache[0]*e1, P1)
         * (-randomizer_cache[1], R2)
         * (-randomizer_cache[1]*e2, P2) */
        secp256k1_scalar_chacha20(&ecmult_context->randomizer_cache[0], &ecmult_context->randomizer_cache[1], ecmult_context->chacha_seed, idx / 4);
    }

    /* R */
    if (idx % 2 == 0) {
        secp256k1_fe rx;
        *sc = ecmult_context->randomizer_cache[(idx / 2) % 2];
        if (!secp256k1_fe_set_b32(&rx, &ecmult_context->sig[idx / 2][0])) {
            return 0;
        }
        if (!secp256k1_ge_set_xquad(pt, &rx)) {
            return 0;
        }
    /* eP */
    } else {
        unsigned char buf[33];
        size_t buflen = sizeof(buf);
        secp256k1_sha256 sha;
        secp256k1_sha256_initialize(&sha);
        secp256k1_sha256_write(&sha, &ecmult_context->sig[idx / 2][0], 32);
        secp256k1_ec_pubkey_serialize(ecmult_context->ctx, buf, &buflen, ecmult_context->pk[idx / 2], SECP256K1_EC_COMPRESSED);
        secp256k1_sha256_write(&sha, buf, buflen);
        secp256k1_sha256_write(&sha, ecmult_context->msg32[idx / 2], 32);
        secp256k1_sha256_finalize(&sha, buf);

        secp256k1_scalar_set_b32(sc, buf, NULL);
        secp256k1_scalar_mul(sc, sc, &ecmult_context->randomizer_cache[(idx / 2) % 2]);

        if (!secp256k1_pubkey_load(ecmult_context->ctx, pt, ecmult_context->pk[idx / 2])) {
            return 0;
        }
    }
    return 1;
}

/** Helper function for batch verification. Hashes signature verification data into the
 *  randomization seed and initializes ecmult_context.
 *
 *  Returns 1 if the randomizer was successfully initialized.
 *
 *  Args:    ctx: a secp256k1 context object
 *  Out: ecmult_context: context for batch_ecmult_callback
 *  In/Out   sha: an initialized sha256 object which hashes the schnorrsig input in order to get a
 *                seed for the randomizer PRNG
 *  In:      sig: array of signatures, or NULL if there are no signatures
 *         msg32: array of messages, or NULL if there are no signatures
 *            pk: array of public keys, or NULL if there are no signatures
 *        n_sigs: number of signatures in above arrays (must be 0 if they are NULL)
 */
int secp256k1_schnorrsig_verify_batch_init_randomizer(const secp256k1_context *ctx, secp256k1_schnorrsig_verify_ecmult_context *ecmult_context, secp256k1_sha256 *sha, const uint8_t *const *sig, const unsigned char *const *msg32, const secp256k1_pubkey *const *pk, size_t n_sigs) {
    size_t i;

    if (n_sigs > 0) {
        ARG_CHECK(sig != NULL);
        ARG_CHECK(msg32 != NULL);
        ARG_CHECK(pk != NULL);
    }

    for (i = 0; i < n_sigs; i++) {
        unsigned char buf[33];
        size_t buflen = sizeof(buf);
        secp256k1_sha256_write(sha, sig[i], 64);
        secp256k1_sha256_write(sha, msg32[i], 32);
        secp256k1_ec_pubkey_serialize(ctx, buf, &buflen, pk[i], SECP256K1_EC_COMPRESSED);
        secp256k1_sha256_write(sha, buf, 32);
    }
    ecmult_context->ctx = ctx;
    ecmult_context->sig = sig;
    ecmult_context->msg32 = msg32;
    ecmult_context->pk = pk;
    ecmult_context->n_sigs = n_sigs;

    return 1;
}

/** Helper function for batch verification. Sums the s part of all signatures multiplied by their
 *  randomizer.
 *
 *  Returns 1 if s is successfully summed.
 *
 *  In/Out: s: the s part of the input sigs is added to this s argument
 *  In:  chacha_seed: PRNG seed for computing randomizers
 *        sig: array of signatures, or NULL if there are no signatures
 *     n_sigs: number of signatures in above array (must be 0 if they are NULL)
 */
int secp256k1_schnorrsig_verify_batch_sum_s(secp256k1_scalar *s, unsigned char *chacha_seed, const uint8_t *const *sig, size_t n_sigs) {
    secp256k1_scalar randomizer_cache[2];
    size_t i;

    secp256k1_scalar_set_int(&randomizer_cache[0], 1);
    for (i = 0; i < n_sigs; i++) {
        int overflow;
        secp256k1_scalar term;
        if (i % 2 == 1) {
            secp256k1_scalar_chacha20(&randomizer_cache[0], &randomizer_cache[1], chacha_seed, i / 2);
        }

        secp256k1_scalar_set_b32(&term, &sig[i][32], &overflow);
        if (overflow) {
            return 0;
        }
        secp256k1_scalar_mul(&term, &term, &randomizer_cache[i % 2]);
        secp256k1_scalar_add(s, s, &term);
    }
    return 1;
}

/* schnorrsig batch verification.
 * Seeds a random number generator with the inputs and derives a random number ai for every
 * signature i. Fails if y-coordinate of any R is not a quadratic residue or if
 * 0 != -(s1 + a2*s2 + ... + au*su)G + R1 + a2*R2 + ... + au*Ru + e1*P1 + (a2*e2)P2 + ... + (au*eu)Pu. */
int secp256k1_schnorrsig_verify_batch(const secp256k1_context *ctx, secp256k1_scratch *scratch, const uint8_t *const *sig, const unsigned char *const *msg32, const secp256k1_pubkey *const *pk, size_t n_sigs) {
    secp256k1_schnorrsig_verify_ecmult_context ecmult_context;
    secp256k1_sha256 sha;
    secp256k1_scalar s;
    secp256k1_gej rj;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(scratch != NULL);
    /* Check that n_sigs is less than half of the maximum size_t value. This is necessary because
     * the number of points given to ecmult_multi is 2*n_sigs. */
    ARG_CHECK(n_sigs <= SIZE_MAX / 2);
    /* Check that n_sigs is less than 2^31 to ensure the same behavior of this function on 32-bit
     * and 64-bit platforms. */
    ARG_CHECK(n_sigs < (size_t)(1 << 31));

    secp256k1_sha256_initialize(&sha);
    if (!secp256k1_schnorrsig_verify_batch_init_randomizer(ctx, &ecmult_context, &sha, sig, msg32, pk, n_sigs)) {
        return 0;
    }
    secp256k1_sha256_finalize(&sha, ecmult_context.chacha_seed);
    secp256k1_scalar_set_int(&ecmult_context.randomizer_cache[0], 1);

    secp256k1_scalar_clear(&s);
    if (!secp256k1_schnorrsig_verify_batch_sum_s(&s, ecmult_context.chacha_seed, sig, n_sigs)) {
        return 0;
    }
    secp256k1_scalar_negate(&s, &s);

    return secp256k1_ecmult_multi_var(&ctx->error_callback, scratch, &rj, &s, secp256k1_schnorrsig_verify_batch_ecmult_callback, (void *) &ecmult_context, 2 * n_sigs)
            && secp256k1_gej_is_infinity(&rj);
}

#endif
