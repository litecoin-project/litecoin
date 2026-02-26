/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BULLETPROOF_UTIL
#define SECP256K1_MODULE_BULLETPROOF_UTIL

/* floor(log2(n)) which returns 0 for 0, since this is used to estimate proof sizes */
SECP256K1_INLINE static size_t secp256k1_floor_lg(size_t n) {
    switch (n) {
    case 0: return 0;
    case 1: return 0;
    case 2: return 1;
    case 3: return 1;
    case 4: return 2;
    case 5: return 2;
    case 6: return 2;
    case 7: return 2;
    case 8: return 3;
    default: {
        size_t i = 0;
        while (n > 1) {
            n /= 2;
            i++;
        }
        return i;
    }
    }
}

SECP256K1_INLINE static size_t secp256k1_popcountl(unsigned long x) {
#ifdef HAVE_BUILTIN_POPCOUNTL
    return __builtin_popcountl(x);
#else
    size_t ret = 0;
    size_t i;
    for (i = 0; i < 64; i++) {
        ret += x & 1;
        x >>= 1;
    }
    return ret;
#endif
}

SECP256K1_INLINE static size_t secp256k1_ctzl(unsigned long x) {
#ifdef HAVE_BUILTIN_CTZL
    return __builtin_ctzl(x);
#else
    size_t i;
    for (i = 0; i < 64; i++) {
        if (x & (1ull << i)) {
            return i;
        }
    }
    /* If no bits are set, the result is __builtin_ctzl is undefined,
     * so we can return whatever we want here. */
    return 0;
#endif
}

static void secp256k1_scalar_dot_product(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b, size_t n) {
    secp256k1_scalar_clear(r);
    while(n--) {
        secp256k1_scalar term;
        secp256k1_scalar_mul(&term, &a[n], &b[n]);
        secp256k1_scalar_add(r, r, &term);
    }
}

static void secp256k1_scalar_inverse_all_var(secp256k1_scalar *r, const secp256k1_scalar *a, size_t len) {
    secp256k1_scalar u;
    size_t i;
    if (len < 1) {
        return;
    }

    VERIFY_CHECK((r + len <= a) || (a + len <= r));

    r[0] = a[0];

    i = 0;
    while (++i < len) {
        secp256k1_scalar_mul(&r[i], &r[i - 1], &a[i]);
    }

    secp256k1_scalar_inverse_var(&u, &r[--i]);

    while (i > 0) {
        size_t j = i--;
        secp256k1_scalar_mul(&r[j], &r[i], &u);
        secp256k1_scalar_mul(&u, &u, &a[j]);
    }

    r[0] = u;
}

SECP256K1_INLINE static void secp256k1_bulletproof_serialize_points(unsigned char *out, secp256k1_ge *pt, size_t n) {
    const size_t bitveclen = (n + 7) / 8;
    size_t i;

    memset(out, 0, bitveclen);
    for (i = 0; i < n; i++) {
        secp256k1_fe pointx;
        pointx = pt[i].x;
        secp256k1_fe_normalize(&pointx);
        secp256k1_fe_get_b32(&out[bitveclen + i*32], &pointx);
        if (!secp256k1_fe_is_quad_var(&pt[i].y)) {
            out[i/8] |= (1ull << (i % 8));
        }
    }
}

SECP256K1_INLINE static int secp256k1_bulletproof_deserialize_point(secp256k1_ge *pt, const unsigned char *data, size_t i, size_t n) {
    const size_t bitveclen = (n + 7) / 8;
    const size_t offset = bitveclen + i*32;
    secp256k1_fe fe;

    secp256k1_fe_set_b32(&fe, &data[offset]);
    if (secp256k1_ge_set_xquad(pt, &fe)) {
        if (data[i / 8] & (1 << (i % 8))) {
            secp256k1_ge_neg(pt, pt);
        }
        return 1;
    } else {
        return 0;
    }
}

static void secp256k1_bulletproof_update_commit(unsigned char *commit, const secp256k1_ge *lpt, const secp256k1_ge *rpt) {
    secp256k1_fe pointx;
    secp256k1_sha256 sha256;
    unsigned char lrparity;
    lrparity = (!secp256k1_fe_is_quad_var(&lpt->y) << 1) + !secp256k1_fe_is_quad_var(&rpt->y);
    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, commit, 32);
    secp256k1_sha256_write(&sha256, &lrparity, 1);
    pointx = lpt->x;
    secp256k1_fe_normalize(&pointx);
    secp256k1_fe_get_b32(commit, &pointx);
    secp256k1_sha256_write(&sha256, commit, 32);
    pointx = rpt->x;
    secp256k1_fe_normalize(&pointx);
    secp256k1_fe_get_b32(commit, &pointx);
    secp256k1_sha256_write(&sha256, commit, 32);
    secp256k1_sha256_finalize(&sha256, commit);
}

static void print_secp256k1_b32(const unsigned char* buf, const char* label) {
    int i;
    if (label != NULL) {
        printf("%s: ", label);
    }
    for (i = 0; i < 32; i++) {
        printf("%02x", buf[i]);
    }
    if (label != NULL) {
        printf("\n");
    }
}

static void print_secp256k1_scalar(const secp256k1_scalar *sc, const char* label) {
    unsigned char buf[32];
    secp256k1_scalar_get_b32(buf, sc);
    print_secp256k1_b32(buf, label);
}

static void print_secp256k1_scalar_array(const secp256k1_scalar *sc, size_t n, const char* label) {
    size_t i;
    if (label != NULL) {
        printf("%s: ", label);
    }
    for (i = 0; i < n; i++) {
        print_secp256k1_scalar(&sc[i], NULL);
        if (i < n - 1) {
            printf(",");
        }
    }
    if (label != NULL) {
        printf("\n");
    }
}

static void print_secp256k1_ge(const secp256k1_ge *ge, const char* label) {
    int i;
    unsigned char buf[32];
    if (label != NULL) {
        printf("%s: ", label);
    }

    secp256k1_fe_get_b32(buf, &ge->x);
    printf("(x: ");
    for (i = 0; i < 32; i++) {
        printf("%02x", buf[i]);
    }
    printf(", y: ");
    secp256k1_fe_get_b32(buf, &ge->y);
    for (i = 0; i < 32; i++) {
        printf("%02x", buf[i]);
    }
    printf(")");

    if (label != NULL) {
        printf("\n");
    }
}

static void print_secp256k1_ge_array(const secp256k1_ge *ge, size_t n, const char* label) {
    size_t i;
    if (label != NULL) {
        printf("%s: ", label);
    }
    for (i = 0; i < n; i++) {
        print_secp256k1_ge(&ge[i], NULL);
        if (i < n - 1) {
            printf(",");
        } else {
            printf("\n");
        }
    }
    if (label != NULL) {
        printf("\n\n");
    }
}

static void print_secp256k1_gej(const secp256k1_gej* gej, const char* label) {
    secp256k1_ge ge;
    secp256k1_ge_set_gej(&ge, gej);
    print_secp256k1_ge(&ge, label);
}

#endif
