/*
 *  Elliptic curve J-PAKE
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * References in the code are to the Thread v1.0 Specification,
 * available to members of the Thread Group http://threadgroup.org/
 */

#include "common.h"

#if defined(MBEDTLS_ECJPAKE_C)

#include "mbedtls/ecjpake.h"
#include "mlkem_native.h"
#include "src/poly.h"
#include "src/poly_k.h"
#include "md_wrap.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

#if !defined(MBEDTLS_ECJPAKE_ALT)

/*
 * Initialize context
 */
void mbedtls_ecjpake_init(mbedtls_ecjpake_context *ctx)
{
    ctx->md_type = MBEDTLS_MD_NONE;

    mbedtls_ecp_point_init(&ctx->Xm1);

    mbedtls_mpi_init(&ctx->xm1);
    mbedtls_mpi_init(&ctx->s);

    mbedtls_mpi_init(&ctx->sid_part);
}

/*
 * Free context
 */
void mbedtls_ecjpake_free(mbedtls_ecjpake_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    ctx->md_type = MBEDTLS_MD_NONE;

    mbedtls_ecp_point_free(&ctx->Xm1);

    mbedtls_mpi_free(&ctx->xm1);
    mbedtls_mpi_free(&ctx->s);

    mbedtls_mpi_free(&ctx->sid_part);
    mbedtls_mpi_free(&ctx->t);

    mbedtls_free(ctx->prs);
    mbedtls_free(ctx->fullsid);
    mbedtls_free(ctx->prk);
}

/*
 * Setup context
 */
int mbedtls_ecjpake_setup(mbedtls_ecjpake_context *ctx,
                          mbedtls_ecjpake_role role,
                          mbedtls_md_type_t hash,
                          mbedtls_ecp_group_id curve,
                          const unsigned char *secret,
                          size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    (void)curve;

    if (role != MBEDTLS_ECJPAKE_CLIENT && role != MBEDTLS_ECJPAKE_SERVER) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    ctx->role = role;

    if ((mbedtls_md_info_from_type(hash)) == NULL) {
        return MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
    }

    ctx->md_type = hash;

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->s, secret, len));

    ctx->prs = mbedtls_calloc(1, len);
    if (!ctx->prs) goto cleanup;
    memcpy(ctx->prs, secret, len);
    ctx->prs_len = len;

cleanup:
    if (ret != 0) {
        mbedtls_ecjpake_free(ctx);
    }

    return ret;
}

int mbedtls_ecjpake_set_point_format(mbedtls_ecjpake_context *ctx,
                                     int point_format)
{
    (void)ctx;
    switch (point_format) {
        case MBEDTLS_ECP_PF_UNCOMPRESSED:
        case MBEDTLS_ECP_PF_COMPRESSED:
            return 0;
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
}

/*
 * Check if context is ready for use
 */
int mbedtls_ecjpake_check(const mbedtls_ecjpake_context *ctx)
{
    if (ctx->md_type == MBEDTLS_MD_NONE ||
        ctx->s.p == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    return 0;
}

/*
 * Size of the temporary buffer for ecjpake_hash:
 * 3 EC points plus their length, plus ID and its length (4 + 6 bytes)
 */
#define ECJPAKE_HASH_BUF_LEN    (3 * (4 + MBEDTLS_ECP_MAX_PT_LEN) + 4 + 6)

static int extend_sid_of_two(const mbedtls_md_info_t *md,
    const uint8_t s1[32], const uint8_t s2[32], uint8_t extended_sid[32]) {
    unsigned char s_concat[64];
    memcpy(s_concat, s1, 32);
    memcpy(s_concat + 32, s2, 32);

    if (mbedtls_hkdf(md,
    (const unsigned char *)OQUAKE_DST "OQUAKE", sizeof(OQUAKE_DST "OQUAKE")-1,
    s_concat, sizeof(s_concat), (const unsigned char *)OQUAKE_DST "SID",
    sizeof(OQUAKE_DST "SID")-1,
    extended_sid, 32))
        return -1;
    return 0;
}

static void write_u32_be(uint8_t *dst, uint32_t v) {
    dst[0] = (v >> 24) & 0xFF;
    dst[1] = (v >> 16) & 0xFF;
    dst[2] = (v >>  8) & 0xFF;
    dst[3] =  v        & 0xFF;
}

static int mbedtls_oquake_encode_sid(const uint8_t *sid, const size_t sid_len, const uint8_t u[16], const uint8_t s[16],
    uint8_t **encoded_sid) {
    uint8_t *temp = mbedtls_calloc(1, 44+sid_len);
    if (!temp) return -1;

    write_u32_be(temp, sid_len);
    memcpy(&temp[4], sid, sid_len);
    write_u32_be(temp+4+sid_len, 16);
    memcpy(&temp[8+sid_len], u, 16);
    write_u32_be(temp+24+sid_len, 16);
    memcpy(&temp[28+sid_len], s, 16);

    *encoded_sid = temp;
    return 0;
}

/*
 * Read and process the first round message
 */
int mbedtls_ecjpake_read_round_one(mbedtls_ecjpake_context *ctx,
                                   const unsigned char *buf,
                                   size_t len)
{
    if (ctx->role == MBEDTLS_ECJPAKE_SERVER) {
        /* responder starts by reading the initiator's sid part
         * (then acts as OQUAKE Client when writing round one
         * and starts regular OQUAKE communication)
         */

        if (len != 32) {
            return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        }

        return mbedtls_mpi_read_binary(&ctx->sid_part, buf, len);

    } else if (ctx->role == MBEDTLS_ECJPAKE_CLIENT) {
        /* initiator reads the responder's init msg being sid part
         */
        if (len != 32) {
            return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        }

        // get own (s1) and peer sid part (s2) from ctx
        uint8_t s1[32];
        if (mbedtls_mpi_write_binary(&ctx->sid_part, s1, 32))
            return MBEDTLS_ERR_MPI_ALLOC_FAILED;
        uint8_t s2[32];
        memcpy(s2, buf, sizeof(s2));

        // extend sid parts to sid
        uint8_t extended_sid[32];
        int res = extend_sid_of_two(mbedtls_md_info_from_type(ctx->md_type), s1, s2, extended_sid);
        if (res != 0) return res;

        // convert sid to fullsid
        uint8_t *fullsid;
        if (mbedtls_oquake_encode_sid(extended_sid, sizeof(extended_sid),
            (unsigned char *)OQUAKE_U_IDENTIFIER, (unsigned char *)OQUAKE_S_IDENTIFIER,
            &fullsid)) return MBEDTLS_ERR_MPI_ALLOC_FAILED;
        const size_t fullsid_len = 3*4 + sizeof(extended_sid) + 32; // 3*32bit + sid_len + 2*16bit
        ctx->fullsid = fullsid;
        ctx->fullsid_len = fullsid_len;

        return 0;

    } else {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

}

/*
 * Generate and write the first round message
 */
int mbedtls_ecjpake_write_round_one(mbedtls_ecjpake_context *ctx,
                                    unsigned char *buf, size_t len, size_t *olen,
                                    int (*f_rng)(void *, unsigned char *, size_t),
                                    void *p_rng)
{

    if (ctx->role == MBEDTLS_ECJPAKE_CLIENT) {
        /* initiator starts by just sending a 32-byte random number to build the sid from
         * together with the sid-part of the responder
         */

        if (len < 32) return MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;

        if (f_rng(p_rng, buf, 32) != 0) {
            mbedtls_platform_zeroize(buf, 32);
            return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
        }

        *olen = 32;
        mbedtls_mpi_read_binary(&ctx->sid_part, buf, 32);
        return 0;

    } else if (ctx->role == MBEDTLS_ECJPAKE_SERVER) {

        int ret = MBEDTLS_ERR_ERROR_GENERIC_ERROR;

        // generate own sid part
        uint8_t s2[32];
        if (f_rng(p_rng, s2, 32) != 0)
            goto cleanup;
        memcpy(buf, s2, 32);
        *olen = 32;

        // get peer sid part from ctx
        uint8_t s1[32];
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&ctx->sid_part, s1, 32));

        // extend sid parts to sid
        uint8_t extended_sid[32];
        if (extend_sid_of_two(mbedtls_md_info_from_type(ctx->md_type), s1, s2, extended_sid))
            goto cleanup;

        // convert sid to fullsid
        uint8_t *fullsid;
        if (mbedtls_oquake_encode_sid(extended_sid, sizeof(extended_sid),
            (unsigned char *)OQUAKE_U_IDENTIFIER, (unsigned char *)OQUAKE_S_IDENTIFIER,
            &fullsid)) return MBEDTLS_ERR_MPI_ALLOC_FAILED;
        const size_t fullsid_len = 3*4 + sizeof(extended_sid) + 32; // 3*32bit + sid_len + 2*16byte
        ctx->fullsid = fullsid;
        ctx->fullsid_len = fullsid_len;

        cleanup:

        return ret;

    } else {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

}

static int hkdf_extract_custom(const mbedtls_md_info_t *md,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm,  size_t ikm_len,
                        uint8_t        *prk)
{
    int ret = -1;
    if (md->size != OQUAKE_SHA256_LEN) goto cleanup;

    if (mbedtls_hkdf_extract(md, salt, salt_len, ikm, ikm_len, prk)) goto cleanup;

    ret = 0;

    cleanup:
        return ret;
}


static int hkdf_expand_custom(const mbedtls_md_info_t *md,
                       const uint8_t *prk,  size_t prk_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t       *okm,  size_t okm_len)
{
    int ret = -1;

    if (md->size != OQUAKE_SHA256_LEN) goto cleanup;

    if (mbedtls_hkdf_expand(md, prk, prk_len, info, info_len, okm, okm_len)) goto cleanup;

    ret = 0;

    cleanup:
        return ret;
}

static int memcmp_const(const void *a, const void *b, size_t len)
{
    const uint8_t *aa = a;
    const uint8_t *bb = b;
    size_t i;
    uint8_t res;

    for (res = 0, i = 0; i < len; i++)
        res |= aa[i] ^ bb[i];

    return res;
}

/*
 * Read and process second round message (C: 7.4.2.5, S: 7.4.2.6)
 */
int mbedtls_ecjpake_read_round_two(mbedtls_ecjpake_context *ctx,
                                   const unsigned char *buf,
                                   size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (ctx->role == MBEDTLS_ECJPAKE_SERVER) {

        uint8_t verifier[64];
        size_t hash_len = 64;
        uint8_t key[32];

        if (len < CRYPTO_CIPHERTEXTBYTES + sizeof(verifier))
            ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;

        // get ciphertext from resp_msg and decapsulate the shared key
        uint8_t ciphertext[CRYPTO_CIPHERTEXTBYTES];
        memcpy(ciphertext, buf, CRYPTO_CIPHERTEXTBYTES);
        if (crypto_kem_dec(key, ciphertext, ctx->sk)) return -1;

        // prepare shared secret computation
        const size_t  ikm_len = OQUAKE_DST_LEN + LABEL_OQUAKE_LEN + ctx->fullsid_len + sizeof(key);
        uint8_t *ikm    = mbedtls_calloc(1, ikm_len);
        if (!ikm) return -1;

        {
            uint8_t *p = ikm;
            memcpy(p, OQUAKE_DST,          OQUAKE_DST_LEN);          p += OQUAKE_DST_LEN;
            memcpy(p, LABEL_OQUAKE, LABEL_OQUAKE_LEN); p += LABEL_OQUAKE_LEN;
            memcpy(p, ctx->fullsid, ctx->fullsid_len);       p += ctx->fullsid_len;
            memcpy(p, key,            sizeof(key));
        }

        // compute and store prk
        const mbedtls_md_info_t *md = mbedtls_md_info_from_type(ctx->md_type);
        uint8_t *prk = mbedtls_calloc(1, md->size);
        if (!prk) {
            ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
            goto cleanup;
        }
        hkdf_extract_custom(md, ctx->prs, ctx->prs_len,
            ikm, ikm_len, prk);
        ctx->prk = prk;

        // compute confirmation value h
        uint8_t confirm[OQUAKE_DST_LEN + 7];
        memcpy(confirm,           OQUAKE_DST,         OQUAKE_DST_LEN);
        memcpy(confirm + OQUAKE_DST_LEN, "confirm",  7);
        const size_t confirm_len = sizeof confirm;
        hkdf_expand_custom(md, prk, md->size, confirm, confirm_len, verifier, sizeof verifier);

        if (memcmp_const(verifier, buf + CRYPTO_CIPHERTEXTBYTES, hash_len)) {
            ret = -1;
            goto cleanup;
        }

        ret = 0;

        cleanup:
        mbedtls_free(ikm);
        return ret;
    } else if (ctx->role == MBEDTLS_ECJPAKE_CLIENT) {
        if (len < 3*OQUAKE_NSEC + KEMELEON_EKBYTES)
            ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;

        // extract masked random and masked ek from init_msg
        ret = mbedtls_mpi_read_binary(&ctx->s, buf, 3*OQUAKE_NSEC);
        ret |= mbedtls_mpi_read_binary(&ctx->t, buf+3*OQUAKE_NSEC, KEMELEON_EKBYTES);
    } else {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    return ret;
}

static int compute_t_pad(const mbedtls_md_info_t *md,
              const uint8_t *PRS,     size_t PRS_len,
              const uint8_t *fullsid, size_t fullsid_len,
              const uint8_t *r,                          /* R_LEN bytes */
              uint8_t        t_pad[KEMELEON_EKBYTES])
{
    int ret = -1;

    /*
     * Build IKM for Extract:
     *   ikm = DST || "OQUAKE" || fullsid || r
     */
    size_t  ikm_len = OQUAKE_DST_LEN + LABEL_OQUAKE_LEN + fullsid_len + R_LEN;
    uint8_t *ikm    = mbedtls_calloc(1, ikm_len);
    if (!ikm) return -1;

    {
        uint8_t *p = ikm;
        memcpy(p, OQUAKE_DST,          OQUAKE_DST_LEN);          p += OQUAKE_DST_LEN;
        memcpy(p, LABEL_OQUAKE, LABEL_OQUAKE_LEN); p += LABEL_OQUAKE_LEN;
        memcpy(p, fullsid,      fullsid_len);       p += fullsid_len;
        memcpy(p, r,            R_LEN);
    }

    /*
     * Build info for Expand:
     *   info = DST || "T_pad"
     */
    uint8_t info[OQUAKE_DST_LEN + LABEL_TPAD_LEN];
    memcpy(info,           OQUAKE_DST,         OQUAKE_DST_LEN);
    memcpy(info + OQUAKE_DST_LEN, LABEL_TPAD,  LABEL_TPAD_LEN);
    const size_t info_len = sizeof info;

    /*
     * prk_T_pad = HKDF-Extract(salt=PRS, ikm=ikm)
     */
    uint8_t prk[OQUAKE_SHA256_LEN];
    if (hkdf_extract_custom(md, PRS, PRS_len, ikm, ikm_len, prk) != 0)
    //if (hmac_sha256(PRS, PRS_len, ikm, ikm_len, prk) !=0);
        goto cleanup;

    /*
     * T_pad = HKDF-Expand(prk=prk_T_pad, info=info, len=CRYPTO_PUBLICKEYBYTES)
     */
    if (hkdf_expand_custom(md, prk, OQUAKE_SHA256_LEN, info, info_len, t_pad, KEMELEON_EKBYTES) != 0)
    //if (hmac_sha256_kdf(prk,  SHA256_LEN,
                        //NULL,              /* label=NULL → HKDF-Expand  */
                        //info, info_len,    /* seed = info               */
                        //t_pad,  KEMELEON_EKBYTES) != 0);
        goto cleanup;

    ret = 0;

cleanup:
    memset(ikm, 0,  ikm_len);
    memset(prk, 0, sizeof prk);
    mbedtls_free(ikm);
    return ret;
}

static int compute_s_pad(const mbedtls_md_info_t *md,
              const uint8_t *PRS,     size_t PRS_len,
              const uint8_t *fullsid, size_t fullsid_len,
              const uint8_t *T,
              uint8_t s_pad[3*OQUAKE_NSEC])                          /* R_LEN bytes */
{
    int ret = -1;

    /*
     */
    size_t  ikm_len = OQUAKE_DST_LEN + LABEL_OQUAKE_LEN + fullsid_len + KEMELEON_EKBYTES;
    uint8_t *ikm    = mbedtls_calloc(1, ikm_len);
    if (!ikm) return -1;

    {
        uint8_t *p = ikm;
        memcpy(p, OQUAKE_DST,          OQUAKE_DST_LEN);          p += OQUAKE_DST_LEN;
        memcpy(p, LABEL_OQUAKE, LABEL_OQUAKE_LEN); p += LABEL_OQUAKE_LEN;
        memcpy(p, fullsid,      fullsid_len);       p += fullsid_len;
        memcpy(p, T,            KEMELEON_EKBYTES);
    }

    /*
     * Build info for Expand:
     *   info = DST || "S_pad"
     */
    uint8_t info[OQUAKE_DST_LEN + LABEL_SPAD_LEN];
    memcpy(info,           OQUAKE_DST,         OQUAKE_DST_LEN);
    memcpy(info + OQUAKE_DST_LEN, LABEL_SPAD,  LABEL_SPAD_LEN);
    const size_t info_len = sizeof info;

    /*
     * prk_T_pad = HKDF-Extract(salt=PRS, ikm=ikm)
     */
    uint8_t prk[OQUAKE_SHA256_LEN];
    /*
     * T_pad = HKDF-Expand(prk=prk_T_pad, info=info, len=CRYPTO_PUBLICKEYBYTES)
     */
    if (hkdf_extract_custom(md, PRS, PRS_len, ikm, ikm_len, prk) != 0)
        goto cleanup;

    /*
     * T_pad = HKDF-Expand(prk=prk_T_pad, info=info, len=CRYPTO_PUBLICKEYBYTES)
     */
    if (hkdf_expand_custom(md, prk, OQUAKE_SHA256_LEN, info, info_len, s_pad, 3*OQUAKE_NSEC) != 0)
        goto cleanup;

    ret = 0;

cleanup:
    mbedtls_platform_zeroize(ikm,   ikm_len);
    mbedtls_platform_zeroize(prk,   sizeof prk);
    mbedtls_free(ikm);
    return ret;
}

static void xor_inplace(uint8_t *a,
                 const uint8_t *b,
                 size_t len)
{
    for (size_t i = 0; i < len; i++) {
        a[i] ^= b[i];   // same as a[i] = a[i] ^ b[i];
    }
}

static int kemeleon_encode_ek(const uint8_t pk[CRYPTO_PUBLICKEYBYTES],
                       uint8_t       ek[KEMELEON_EKBYTES],
                       mbedtls_f_rng_t *f_rng, void *p_rng)
{
    int ret = 0;

    mbedtls_mpi r;
    mbedtls_mpi_init(&r);               /* accumulator: sum a[i] * q^i      */
    mbedtls_mpi qpow;
    mbedtls_mpi_init(&qpow);            /* q^i, advances per coefficient    */
    mbedtls_mpi bq;
    mbedtls_mpi_init(&bq);              /* constant q = 3329                */
    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);             /* scratch                          */
    mbedtls_mpi qn;
    mbedtls_mpi_init(&qn);              /* q^n  (denominator for m)         */
    mbedtls_mpi bound;
    mbedtls_mpi_init(&bound);           /* 2^(b+t)                          */
    mbedtls_mpi m;
    mbedtls_mpi_init(&m);               /* random m in [0, floor((2^(b+t)-r)/q^n)] */

    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&bq, 3329u));
    //BN_set_word(bq, 3329u);

    /* Load and reduce polyvec */
    mlk_polyvec a;
    mlk_polyvec_frombytes(&a, pk);
    mlk_polyvec_reduce(&a);   /* ensure coefficients in [0, q-1] */

    for (int poly = 0; poly < MLKEM_K; poly++) {

        /* ----------------------------------------------------------------
         * Accumulate: r = sum_{i=0}^{n-1} a[i] * q^i
         * ---------------------------------------------------------------- */
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&r, 0));
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&qpow, 1));
        //BN_zero(r);
        //BN_one(qpow);

        for (int i = 0; i < MLKEM_N; i++) {
            uint16_t coeff = (uint16_t)a.vec[poly].coeffs[i]; /* [0, q-1] */
            MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&tmp, coeff));
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tmp, &tmp, &qpow));     /* tmp = a[i] * q^i  */
            MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&r, &r, &tmp));          /* r  += a[i] * q^i  */
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&qpow, &qpow, &bq));     /* qpow = q^(i+1)    */
        }
        /* qpow == q^n after the loop */
        MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&qn, &qpow));

        /* ----------------------------------------------------------------
         * Compute bound = 2^(b+t)
         * b = KEMELEON_B_BITS = 2996, t = KEMELEON_T_BITS = 128
         * ---------------------------------------------------------------- */
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&bound, 0));
        /* 2^(b+t) */
        MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&bound, KEMELEON_B_BITS + KEMELEON_T_BITS, 1));

        /* ----------------------------------------------------------------
         * Sample m uniformly at random from [0, floor((2^(b+t) - r) / q^n)]
         *
         * range = floor((2^(b+t) - r) / q^n)
         * m <--$ [0, range]
         * ---------------------------------------------------------------- */
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&tmp, &bound, &r));         /* tmp   = 2^(b+t) - r           */
        MBEDTLS_MPI_CHK(mbedtls_mpi_div_mpi(&tmp, NULL, &tmp, &qn)); /* tmp   = floor((2^(b+t)-r)/q^n)*/
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&tmp, &tmp, 1));                /* tmp   = range + 1 (exclusive)  */
        MBEDTLS_MPI_CHK(mbedtls_mpi_random(&m, 0, &tmp, f_rng, p_rng));   /* m <--$ [0, range]              */

        /* ----------------------------------------------------------------
         * Output = r + m * q^n
         * ---------------------------------------------------------------- */
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tmp, &m, &qn));    /* tmp = m * q^n                 */
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&r, &r, &tmp));     /* r   = r + m * q^n             */

        /* Serialise to exactly KEMELEON_PER_POLY_BYTES big-endian bytes */
        uint8_t *out = ek + poly * KEMELEON_PER_POLY_BYTES;
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&r, out, KEMELEON_PER_POLY_BYTES));

    }

    /* Append rho (seed) */
    memcpy(ek + MLKEM_K * KEMELEON_PER_POLY_BYTES,
           pk + MLKEM_POLYVECBYTES,
           MLKEM_SYMBYTES);

    /* if no failure has come up until here ret shall not be set to an error code */
    goto cleanup_nofailure;

    cleanup:
    ret = -1;

    cleanup_nofailure:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&qpow);
    mbedtls_mpi_free(&bq);
    mbedtls_mpi_free(&tmp);
    mbedtls_mpi_free(&qn);
    mbedtls_mpi_free(&bound);
    mbedtls_mpi_free(&m);
    return ret;
}

static int mbedtls_oquake_init_step(const mbedtls_md_info_t *md,
                    unsigned char *prs, const size_t prs_len,
                    mbedtls_f_rng_t *f_rng, void *p_rng,
                    mbedtls_ecjpake_context *ctx, uint8_t *init_msg) {

    int ret = MBEDTLS_ERR_ERROR_GENERIC_ERROR;

    // initialise buffer for seed
    uint8_t seed[2*MLKEM_SYMBYTES];

    // generate seed and keypair
    if (f_rng(p_rng, seed, 2*MLKEM_SYMBYTES)) goto cleanup;

    // generate keypair and encode public key for indistinguishability
    uint8_t ek[KEMELEON_EKBYTES];
    if (crypto_kem_keypair_derand(ctx->pk, ctx->sk, seed)) goto cleanup;
    kemeleon_encode_ek(ctx->pk, ek, f_rng, p_rng);

    // mask encoded public key ek using randomness r
    uint8_t r[3*OQUAKE_NSEC];
    if (f_rng(p_rng, r, sizeof r)) return -1;
    uint8_t T_pad[KEMELEON_EKBYTES];
    compute_t_pad(md, prs, prs_len, ctx->fullsid, ctx->fullsid_len, r, T_pad);
    xor_inplace(ek, T_pad, sizeof T_pad);

    // mask randomness r using masked ek
    uint8_t s_pad[3*OQUAKE_NSEC];
    compute_s_pad(md, prs, prs_len, ctx->fullsid, ctx->fullsid_len, ek, s_pad);
    xor_inplace(r, s_pad, sizeof s_pad);

    // init_msg: r || ek
    memcpy(init_msg, r, sizeof(r));
    memcpy(init_msg + sizeof(r), ek, sizeof(ek));

    // configure ctx
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->s, r, sizeof(r)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->t, ek, sizeof(ek)));
    ret = 0;

    cleanup:

    return ret;

}

static int kemeleon_decode_ek(const uint8_t ek[KEMELEON_EKBYTES],
                       uint8_t       pk[CRYPTO_PUBLICKEYBYTES])
{
    int ret = 0;

    mbedtls_mpi r;
    mbedtls_mpi_init(&r);
    mbedtls_mpi bq;
    mbedtls_mpi_init(&bq);
    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);

    mbedtls_mpi_lset(&bq, 3329u);

    mlk_polyvec a;

    for (int poly = 0; poly < MLKEM_K; poly++) {
        /* Load encoded polynomial */
        const uint8_t *in = ek + poly * KEMELEON_PER_POLY_BYTES;
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&r, in, KEMELEON_PER_POLY_BYTES));

        /* VectorDecode: r = r mod q^n, then extract coefficients
         * a[i] = r % q; r = r / q  */
        for (int i = 0; i < MLKEM_N; i++) {
            MBEDTLS_MPI_CHK(mbedtls_mpi_div_mpi(&r, &tmp, &r, &bq));    /* tmp = r % q, r = r / q */
            uint8_t tmp_as_int[2];
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&tmp, tmp_as_int, 2));
            a.vec[poly].coeffs[i] = (int16_t)(tmp_as_int[0]<<8 | tmp_as_int[1]);
        }
    }

    /* Re-encode polyvec to bytes */
    mlk_polyvec_tobytes(pk, &a);

    /* Copy rho */
    memcpy(pk + MLKEM_POLYVECBYTES,
           ek + MLKEM_K * KEMELEON_PER_POLY_BYTES,
           MLKEM_SYMBYTES);

    /* when no failure has come up until here ret shall not be set to an error code */
    goto cleanup_nofailure;

    cleanup:
    ret = -1;

    cleanup_nofailure:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&bq);
    mbedtls_mpi_free(&tmp);
    return ret;
}

static int mbedtls_oquake_respond(mbedtls_ecjpake_context *ctx,
                    const mbedtls_md_info_t *md,
                    const unsigned char *prs, const size_t prs_len,
                    uint8_t *resp_msg) {

    int ret = MBEDTLS_ERR_ERROR_GENERIC_ERROR;

    uint8_t *ikm = NULL;

    if (md->size != OQUAKE_SHA256_LEN) return ret;

    // read masked random and masked ek from ctx
    const size_t fullsid_len = ctx->fullsid_len;

    uint8_t msg_s[3*OQUAKE_NSEC];
    uint8_t ek[KEMELEON_EKBYTES];
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&ctx->s, msg_s, sizeof(msg_s)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&ctx->t, ek, sizeof(ek)));

    // reconstruct random and ek from masked values
    uint8_t s_pad[3*OQUAKE_NSEC];
    compute_s_pad(md, prs, prs_len, ctx->fullsid, fullsid_len, ek, s_pad);
    xor_inplace(msg_s, s_pad, sizeof s_pad);
    uint8_t T_pad[KEMELEON_EKBYTES];
    compute_t_pad(md, prs, prs_len, ctx->fullsid, fullsid_len, msg_s, T_pad);
    xor_inplace(ek, T_pad, sizeof T_pad);

    // decode encoded pk
    uint8_t pk[MLKEM768_PUBLICKEYBYTES];
    kemeleon_decode_ek(ek, pk);

    // use kem to generate and encapsulate key using pk
    uint8_t ciphertext[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key[32];
    if (crypto_kem_enc(ciphertext, key, pk)) goto cleanup;

    // input keying material for KDF Extraction
    const size_t  ikm_len = OQUAKE_DST_LEN + LABEL_OQUAKE_LEN + fullsid_len + sizeof(key);
    ikm    = mbedtls_calloc(1, ikm_len);
    if (!ikm) goto cleanup; ;
    {
        uint8_t *p = ikm;
        memcpy(p, OQUAKE_DST,          OQUAKE_DST_LEN);          p += OQUAKE_DST_LEN;
        memcpy(p, LABEL_OQUAKE, LABEL_OQUAKE_LEN); p += LABEL_OQUAKE_LEN;
        memcpy(p, ctx->fullsid,      fullsid_len);              p += fullsid_len;
        memcpy(p, key,            sizeof(key));
    }

    // extract pseudo random key from input keying material
    uint8_t *prk = mbedtls_calloc(1, OQUAKE_SHA256_LEN);
    if (!prk) goto cleanup;
    uint8_t h[64];
    hkdf_extract_custom(md, prs, prs_len, ikm, ikm_len, prk);
    ctx->prk = prk;

    // expand prk to get confirmation value h
    uint8_t confirm[OQUAKE_DST_LEN + 7];
    memcpy(confirm,           OQUAKE_DST,         OQUAKE_DST_LEN);
    memcpy(confirm + OQUAKE_DST_LEN, "confirm",  7);
    const size_t confirm_len = sizeof confirm;
    hkdf_expand_custom(md, prk, md->size, confirm, confirm_len, h, sizeof h);

    // build response message
    memcpy(resp_msg, ciphertext, CRYPTO_CIPHERTEXTBYTES);
    memcpy(resp_msg+CRYPTO_CIPHERTEXTBYTES, h, sizeof h);

    ret = 0;

    cleanup:
    mbedtls_free(ikm);

    return ret;

}

/*
 * Generate and write the second round message (S: 7.4.2.5, C: 7.4.2.6)
 */
int mbedtls_ecjpake_write_round_two(mbedtls_ecjpake_context *ctx,
                                    unsigned char *buf, size_t len, size_t *olen,
                                    int (*f_rng)(void *, unsigned char *, size_t),
                                    void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (ctx->role == MBEDTLS_ECJPAKE_SERVER) {

        *olen = 3*OQUAKE_NSEC + KEMELEON_EKBYTES;

        // write init msg to buf
        if (len < *olen) {
            ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
            goto cleanup;
        }

        // generate init message by performing OQUAKE.INIT step
        if (mbedtls_oquake_init_step(mbedtls_md_info_from_type(ctx->md_type),
            ctx->prs, ctx->prs_len, f_rng, p_rng, ctx, buf))
        {
            goto cleanup;
        }

    } else if (ctx->role == MBEDTLS_ECJPAKE_CLIENT) {
        *olen = CRYPTO_CIPHERTEXTBYTES + 64;
        if (len < *olen) {
            ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
            goto cleanup;
        }

        mbedtls_oquake_respond(ctx, mbedtls_md_info_from_type(ctx->md_type),
            ctx->prs, ctx->prs_len, buf);


    } else {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }
    ret = 0;

    cleanup:

    return ret;
}

/*
 * Derive PMS (7.4.2.7 / 7.4.2.8)
 */
static int mbedtls_ecjpake_derive_k(mbedtls_ecjpake_context *ctx,
                                    mbedtls_ecp_point *K,
                                    int (*f_rng)(void *, unsigned char *, size_t),
                                    void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi m_xm2_s, one;

    mbedtls_mpi_init(&m_xm2_s);
    mbedtls_mpi_init(&one);

    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&one, 1));

    /*
     * Client:  K = ( Xs - X4  * x2  * s ) * x2
     * Server:  K = ( Xc - X2  * x4  * s ) * x4
     * Unified: K = ( Xp - Xp2 * xm2 * s ) * xm2
     */
    (void)ctx;
    (void)K;
    (void)f_rng;
    (void)p_rng;

cleanup:
    mbedtls_mpi_free(&m_xm2_s);
    mbedtls_mpi_free(&one);

    return ret;
}

static int mbedtls_oquake_finish(const mbedtls_ecjpake_context *ctx, uint8_t *ss) {

    // compute shared secret using KDF
    uint8_t sk[OQUAKE_DST_LEN + 2];
    memcpy(sk,           OQUAKE_DST,         OQUAKE_DST_LEN);
    memcpy(sk + OQUAKE_DST_LEN, "sk",  2);
    const size_t sk_len = sizeof sk;
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(ctx->md_type);
    hkdf_expand_custom(md, ctx->prk, md->size, sk, sk_len, ss, 32);

    return 0;

}

int mbedtls_ecjpake_derive_secret(mbedtls_ecjpake_context *ctx,
                                  unsigned char *buf, size_t len, size_t *olen,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng)
{
    unsigned char tmp[1];
    int ret = f_rng(p_rng, tmp, 1);

    ret = MBEDTLS_ERR_ERROR_GENERIC_ERROR;

    if (len < mbedtls_md_info_from_type(ctx->md_type)->size) {
        ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    *olen = mbedtls_md_info_from_type(ctx->md_type)->size;
    mbedtls_oquake_finish(ctx, buf);
    ret = 0;

    cleanup:

    return ret;
}

int mbedtls_ecjpake_write_shared_key(mbedtls_ecjpake_context *ctx,
                                     unsigned char *buf, size_t len, size_t *olen,
                                     int (*f_rng)(void *, unsigned char *, size_t),
                                     void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point K;

    mbedtls_ecp_point_init(&K);

    ret = mbedtls_ecjpake_derive_k(ctx, &K, f_rng, p_rng);
    if (ret) {
        goto cleanup;
    }

    (void)buf;
    (void)len;
    *olen = 0;
    if (ret != 0) {
        goto cleanup;
    }

cleanup:
    mbedtls_ecp_point_free(&K);

    return ret;
}

#undef ID_MINE
#undef ID_PEER

#endif /* ! MBEDTLS_ECJPAKE_ALT */

#if defined(MBEDTLS_SELF_TEST)

#include "mbedtls/platform.h"

#if !defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED) || \
    !defined(MBEDTLS_MD_CAN_SHA256)
int mbedtls_ecjpake_self_test(int verbose)
{
    (void) verbose;
    return 0;
}
#else

static const unsigned char ecjpake_test_password[] = {
    0x74, 0x68, 0x72, 0x65, 0x61, 0x64, 0x6a, 0x70, 0x61, 0x6b, 0x65, 0x74,
    0x65, 0x73, 0x74
};

#if !defined(MBEDTLS_ECJPAKE_ALT)

static const unsigned char ecjpake_test_x1[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x21
};

static const unsigned char ecjpake_test_x2[] = {
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
    0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
    0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x81
};

static const unsigned char ecjpake_test_x3[] = {
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
    0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
    0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x81
};

static const unsigned char ecjpake_test_x4[] = {
    0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc,
    0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
    0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe1
};

static const unsigned char ecjpake_test_cli_one[] = {
    0x41, 0x04, 0xac, 0xcf, 0x01, 0x06, 0xef, 0x85, 0x8f, 0xa2, 0xd9, 0x19,
    0x33, 0x13, 0x46, 0x80, 0x5a, 0x78, 0xb5, 0x8b, 0xba, 0xd0, 0xb8, 0x44,
    0xe5, 0xc7, 0x89, 0x28, 0x79, 0x14, 0x61, 0x87, 0xdd, 0x26, 0x66, 0xad,
    0xa7, 0x81, 0xbb, 0x7f, 0x11, 0x13, 0x72, 0x25, 0x1a, 0x89, 0x10, 0x62,
    0x1f, 0x63, 0x4d, 0xf1, 0x28, 0xac, 0x48, 0xe3, 0x81, 0xfd, 0x6e, 0xf9,
    0x06, 0x07, 0x31, 0xf6, 0x94, 0xa4, 0x41, 0x04, 0x1d, 0xd0, 0xbd, 0x5d,
    0x45, 0x66, 0xc9, 0xbe, 0xd9, 0xce, 0x7d, 0xe7, 0x01, 0xb5, 0xe8, 0x2e,
    0x08, 0xe8, 0x4b, 0x73, 0x04, 0x66, 0x01, 0x8a, 0xb9, 0x03, 0xc7, 0x9e,
    0xb9, 0x82, 0x17, 0x22, 0x36, 0xc0, 0xc1, 0x72, 0x8a, 0xe4, 0xbf, 0x73,
    0x61, 0x0d, 0x34, 0xde, 0x44, 0x24, 0x6e, 0xf3, 0xd9, 0xc0, 0x5a, 0x22,
    0x36, 0xfb, 0x66, 0xa6, 0x58, 0x3d, 0x74, 0x49, 0x30, 0x8b, 0xab, 0xce,
    0x20, 0x72, 0xfe, 0x16, 0x66, 0x29, 0x92, 0xe9, 0x23, 0x5c, 0x25, 0x00,
    0x2f, 0x11, 0xb1, 0x50, 0x87, 0xb8, 0x27, 0x38, 0xe0, 0x3c, 0x94, 0x5b,
    0xf7, 0xa2, 0x99, 0x5d, 0xda, 0x1e, 0x98, 0x34, 0x58, 0x41, 0x04, 0x7e,
    0xa6, 0xe3, 0xa4, 0x48, 0x70, 0x37, 0xa9, 0xe0, 0xdb, 0xd7, 0x92, 0x62,
    0xb2, 0xcc, 0x27, 0x3e, 0x77, 0x99, 0x30, 0xfc, 0x18, 0x40, 0x9a, 0xc5,
    0x36, 0x1c, 0x5f, 0xe6, 0x69, 0xd7, 0x02, 0xe1, 0x47, 0x79, 0x0a, 0xeb,
    0x4c, 0xe7, 0xfd, 0x65, 0x75, 0xab, 0x0f, 0x6c, 0x7f, 0xd1, 0xc3, 0x35,
    0x93, 0x9a, 0xa8, 0x63, 0xba, 0x37, 0xec, 0x91, 0xb7, 0xe3, 0x2b, 0xb0,
    0x13, 0xbb, 0x2b, 0x41, 0x04, 0xa4, 0x95, 0x58, 0xd3, 0x2e, 0xd1, 0xeb,
    0xfc, 0x18, 0x16, 0xaf, 0x4f, 0xf0, 0x9b, 0x55, 0xfc, 0xb4, 0xca, 0x47,
    0xb2, 0xa0, 0x2d, 0x1e, 0x7c, 0xaf, 0x11, 0x79, 0xea, 0x3f, 0xe1, 0x39,
    0x5b, 0x22, 0xb8, 0x61, 0x96, 0x40, 0x16, 0xfa, 0xba, 0xf7, 0x2c, 0x97,
    0x56, 0x95, 0xd9, 0x3d, 0x4d, 0xf0, 0xe5, 0x19, 0x7f, 0xe9, 0xf0, 0x40,
    0x63, 0x4e, 0xd5, 0x97, 0x64, 0x93, 0x77, 0x87, 0xbe, 0x20, 0xbc, 0x4d,
    0xee, 0xbb, 0xf9, 0xb8, 0xd6, 0x0a, 0x33, 0x5f, 0x04, 0x6c, 0xa3, 0xaa,
    0x94, 0x1e, 0x45, 0x86, 0x4c, 0x7c, 0xad, 0xef, 0x9c, 0xf7, 0x5b, 0x3d,
    0x8b, 0x01, 0x0e, 0x44, 0x3e, 0xf0
};

static const unsigned char ecjpake_test_srv_one[] = {
    0x41, 0x04, 0x7e, 0xa6, 0xe3, 0xa4, 0x48, 0x70, 0x37, 0xa9, 0xe0, 0xdb,
    0xd7, 0x92, 0x62, 0xb2, 0xcc, 0x27, 0x3e, 0x77, 0x99, 0x30, 0xfc, 0x18,
    0x40, 0x9a, 0xc5, 0x36, 0x1c, 0x5f, 0xe6, 0x69, 0xd7, 0x02, 0xe1, 0x47,
    0x79, 0x0a, 0xeb, 0x4c, 0xe7, 0xfd, 0x65, 0x75, 0xab, 0x0f, 0x6c, 0x7f,
    0xd1, 0xc3, 0x35, 0x93, 0x9a, 0xa8, 0x63, 0xba, 0x37, 0xec, 0x91, 0xb7,
    0xe3, 0x2b, 0xb0, 0x13, 0xbb, 0x2b, 0x41, 0x04, 0x09, 0xf8, 0x5b, 0x3d,
    0x20, 0xeb, 0xd7, 0x88, 0x5c, 0xe4, 0x64, 0xc0, 0x8d, 0x05, 0x6d, 0x64,
    0x28, 0xfe, 0x4d, 0xd9, 0x28, 0x7a, 0xa3, 0x65, 0xf1, 0x31, 0xf4, 0x36,
    0x0f, 0xf3, 0x86, 0xd8, 0x46, 0x89, 0x8b, 0xc4, 0xb4, 0x15, 0x83, 0xc2,
    0xa5, 0x19, 0x7f, 0x65, 0xd7, 0x87, 0x42, 0x74, 0x6c, 0x12, 0xa5, 0xec,
    0x0a, 0x4f, 0xfe, 0x2f, 0x27, 0x0a, 0x75, 0x0a, 0x1d, 0x8f, 0xb5, 0x16,
    0x20, 0x93, 0x4d, 0x74, 0xeb, 0x43, 0xe5, 0x4d, 0xf4, 0x24, 0xfd, 0x96,
    0x30, 0x6c, 0x01, 0x17, 0xbf, 0x13, 0x1a, 0xfa, 0xbf, 0x90, 0xa9, 0xd3,
    0x3d, 0x11, 0x98, 0xd9, 0x05, 0x19, 0x37, 0x35, 0x14, 0x41, 0x04, 0x19,
    0x0a, 0x07, 0x70, 0x0f, 0xfa, 0x4b, 0xe6, 0xae, 0x1d, 0x79, 0xee, 0x0f,
    0x06, 0xae, 0xb5, 0x44, 0xcd, 0x5a, 0xdd, 0xaa, 0xbe, 0xdf, 0x70, 0xf8,
    0x62, 0x33, 0x21, 0x33, 0x2c, 0x54, 0xf3, 0x55, 0xf0, 0xfb, 0xfe, 0xc7,
    0x83, 0xed, 0x35, 0x9e, 0x5d, 0x0b, 0xf7, 0x37, 0x7a, 0x0f, 0xc4, 0xea,
    0x7a, 0xce, 0x47, 0x3c, 0x9c, 0x11, 0x2b, 0x41, 0xcc, 0xd4, 0x1a, 0xc5,
    0x6a, 0x56, 0x12, 0x41, 0x04, 0x36, 0x0a, 0x1c, 0xea, 0x33, 0xfc, 0xe6,
    0x41, 0x15, 0x64, 0x58, 0xe0, 0xa4, 0xea, 0xc2, 0x19, 0xe9, 0x68, 0x31,
    0xe6, 0xae, 0xbc, 0x88, 0xb3, 0xf3, 0x75, 0x2f, 0x93, 0xa0, 0x28, 0x1d,
    0x1b, 0xf1, 0xfb, 0x10, 0x60, 0x51, 0xdb, 0x96, 0x94, 0xa8, 0xd6, 0xe8,
    0x62, 0xa5, 0xef, 0x13, 0x24, 0xa3, 0xd9, 0xe2, 0x78, 0x94, 0xf1, 0xee,
    0x4f, 0x7c, 0x59, 0x19, 0x99, 0x65, 0xa8, 0xdd, 0x4a, 0x20, 0x91, 0x84,
    0x7d, 0x2d, 0x22, 0xdf, 0x3e, 0xe5, 0x5f, 0xaa, 0x2a, 0x3f, 0xb3, 0x3f,
    0xd2, 0xd1, 0xe0, 0x55, 0xa0, 0x7a, 0x7c, 0x61, 0xec, 0xfb, 0x8d, 0x80,
    0xec, 0x00, 0xc2, 0xc9, 0xeb, 0x12
};

static const unsigned char ecjpake_test_srv_two[] = {
    0x03, 0x00, 0x17, 0x41, 0x04, 0x0f, 0xb2, 0x2b, 0x1d, 0x5d, 0x11, 0x23,
    0xe0, 0xef, 0x9f, 0xeb, 0x9d, 0x8a, 0x2e, 0x59, 0x0a, 0x1f, 0x4d, 0x7c,
    0xed, 0x2c, 0x2b, 0x06, 0x58, 0x6e, 0x8f, 0x2a, 0x16, 0xd4, 0xeb, 0x2f,
    0xda, 0x43, 0x28, 0xa2, 0x0b, 0x07, 0xd8, 0xfd, 0x66, 0x76, 0x54, 0xca,
    0x18, 0xc5, 0x4e, 0x32, 0xa3, 0x33, 0xa0, 0x84, 0x54, 0x51, 0xe9, 0x26,
    0xee, 0x88, 0x04, 0xfd, 0x7a, 0xf0, 0xaa, 0xa7, 0xa6, 0x41, 0x04, 0x55,
    0x16, 0xea, 0x3e, 0x54, 0xa0, 0xd5, 0xd8, 0xb2, 0xce, 0x78, 0x6b, 0x38,
    0xd3, 0x83, 0x37, 0x00, 0x29, 0xa5, 0xdb, 0xe4, 0x45, 0x9c, 0x9d, 0xd6,
    0x01, 0xb4, 0x08, 0xa2, 0x4a, 0xe6, 0x46, 0x5c, 0x8a, 0xc9, 0x05, 0xb9,
    0xeb, 0x03, 0xb5, 0xd3, 0x69, 0x1c, 0x13, 0x9e, 0xf8, 0x3f, 0x1c, 0xd4,
    0x20, 0x0f, 0x6c, 0x9c, 0xd4, 0xec, 0x39, 0x22, 0x18, 0xa5, 0x9e, 0xd2,
    0x43, 0xd3, 0xc8, 0x20, 0xff, 0x72, 0x4a, 0x9a, 0x70, 0xb8, 0x8c, 0xb8,
    0x6f, 0x20, 0xb4, 0x34, 0xc6, 0x86, 0x5a, 0xa1, 0xcd, 0x79, 0x06, 0xdd,
    0x7c, 0x9b, 0xce, 0x35, 0x25, 0xf5, 0x08, 0x27, 0x6f, 0x26, 0x83, 0x6c
};

static const unsigned char ecjpake_test_cli_two[] = {
    0x41, 0x04, 0x69, 0xd5, 0x4e, 0xe8, 0x5e, 0x90, 0xce, 0x3f, 0x12, 0x46,
    0x74, 0x2d, 0xe5, 0x07, 0xe9, 0x39, 0xe8, 0x1d, 0x1d, 0xc1, 0xc5, 0xcb,
    0x98, 0x8b, 0x58, 0xc3, 0x10, 0xc9, 0xfd, 0xd9, 0x52, 0x4d, 0x93, 0x72,
    0x0b, 0x45, 0x54, 0x1c, 0x83, 0xee, 0x88, 0x41, 0x19, 0x1d, 0xa7, 0xce,
    0xd8, 0x6e, 0x33, 0x12, 0xd4, 0x36, 0x23, 0xc1, 0xd6, 0x3e, 0x74, 0x98,
    0x9a, 0xba, 0x4a, 0xff, 0xd1, 0xee, 0x41, 0x04, 0x07, 0x7e, 0x8c, 0x31,
    0xe2, 0x0e, 0x6b, 0xed, 0xb7, 0x60, 0xc1, 0x35, 0x93, 0xe6, 0x9f, 0x15,
    0xbe, 0x85, 0xc2, 0x7d, 0x68, 0xcd, 0x09, 0xcc, 0xb8, 0xc4, 0x18, 0x36,
    0x08, 0x91, 0x7c, 0x5c, 0x3d, 0x40, 0x9f, 0xac, 0x39, 0xfe, 0xfe, 0xe8,
    0x2f, 0x72, 0x92, 0xd3, 0x6f, 0x0d, 0x23, 0xe0, 0x55, 0x91, 0x3f, 0x45,
    0xa5, 0x2b, 0x85, 0xdd, 0x8a, 0x20, 0x52, 0xe9, 0xe1, 0x29, 0xbb, 0x4d,
    0x20, 0x0f, 0x01, 0x1f, 0x19, 0x48, 0x35, 0x35, 0xa6, 0xe8, 0x9a, 0x58,
    0x0c, 0x9b, 0x00, 0x03, 0xba, 0xf2, 0x14, 0x62, 0xec, 0xe9, 0x1a, 0x82,
    0xcc, 0x38, 0xdb, 0xdc, 0xae, 0x60, 0xd9, 0xc5, 0x4c
};

static const unsigned char ecjpake_test_shared_key[] = {
    0x04, 0x01, 0xab, 0xe9, 0xf2, 0xc7, 0x3a, 0x99, 0x14, 0xcb, 0x1f, 0x80,
    0xfb, 0x9d, 0xdb, 0x7e, 0x00, 0x12, 0xa8, 0x9c, 0x2f, 0x39, 0x27, 0x79,
    0xf9, 0x64, 0x40, 0x14, 0x75, 0xea, 0xc1, 0x31, 0x28, 0x43, 0x8f, 0xe1,
    0x12, 0x41, 0xd6, 0xc1, 0xe5, 0x5f, 0x7b, 0x80, 0x88, 0x94, 0xc9, 0xc0,
    0x27, 0xa3, 0x34, 0x41, 0xf5, 0xcb, 0xa1, 0xfe, 0x6c, 0xc7, 0xe6, 0x12,
    0x17, 0xc3, 0xde, 0x27, 0xb4,
};

static const unsigned char ecjpake_test_pms[] = {
    0xf3, 0xd4, 0x7f, 0x59, 0x98, 0x44, 0xdb, 0x92, 0xa5, 0x69, 0xbb, 0xe7,
    0x98, 0x1e, 0x39, 0xd9, 0x31, 0xfd, 0x74, 0x3b, 0xf2, 0x2e, 0x98, 0xf9,
    0xb4, 0x38, 0xf7, 0x19, 0xd3, 0xc4, 0xf3, 0x51
};

/*
 * PRNG for test - !!!INSECURE NEVER USE IN PRODUCTION!!!
 *
 * This is the linear congruential generator from numerical recipes,
 * except we only use the low byte as the output. See
 * https://en.wikipedia.org/wiki/Linear_congruential_generator#Parameters_in_common_use
 */
static int self_test_rng(void *ctx, unsigned char *out, size_t len)
{
    static uint32_t state = 42;

    (void) ctx;

    for (size_t i = 0; i < len; i++) {
        state = state * 1664525u + 1013904223u;
        out[i] = (unsigned char) state;
    }

    return 0;
}

/* Load my private keys and generate the corresponding public keys */
static int ecjpake_test_load(mbedtls_ecjpake_context *ctx,
                             const unsigned char *xm1, size_t len1,
                             const unsigned char *xm2, size_t len2)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->xm1, xm1, len1));
    (void)xm2;
    (void)len2;

cleanup:
    return ret;
}

#endif /* ! MBEDTLS_ECJPAKE_ALT */

/* For tests we don't need a secure RNG;
 * use the LGC from Numerical Recipes for simplicity */
static int ecjpake_lgc(void *p, unsigned char *out, size_t len)
{
    static uint32_t x = 42;
    (void) p;

    while (len > 0) {
        size_t use_len = len > 4 ? 4 : len;
        x = 1664525 * x + 1013904223;
        memcpy(out, &x, use_len);
        out += use_len;
        len -= use_len;
    }

    return 0;
}

#define TEST_ASSERT(x)    \
    do {                    \
        if (x)             \
        ret = 0;        \
        else                \
        {                   \
            ret = 1;        \
            goto cleanup;   \
        }                   \
    } while (0)

/*
 * Checkup routine
 */
int mbedtls_ecjpake_self_test(int verbose)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecjpake_context cli;
    mbedtls_ecjpake_context srv;
    unsigned char buf[512], pms[32];
    size_t len, pmslen;

    mbedtls_ecjpake_init(&cli);
    mbedtls_ecjpake_init(&srv);

    if (verbose != 0) {
        mbedtls_printf("  ECJPAKE test #0 (setup): ");
    }

    TEST_ASSERT(mbedtls_ecjpake_setup(&cli, MBEDTLS_ECJPAKE_CLIENT,
                                      MBEDTLS_MD_SHA256, MBEDTLS_ECP_DP_SECP256R1,
                                      ecjpake_test_password,
                                      sizeof(ecjpake_test_password)) == 0);

    TEST_ASSERT(mbedtls_ecjpake_setup(&srv, MBEDTLS_ECJPAKE_SERVER,
                                      MBEDTLS_MD_SHA256, MBEDTLS_ECP_DP_SECP256R1,
                                      ecjpake_test_password,
                                      sizeof(ecjpake_test_password)) == 0);

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

    if (verbose != 0) {
        mbedtls_printf("  ECJPAKE test #1 (random handshake): ");
    }

    TEST_ASSERT(mbedtls_ecjpake_write_round_one(&cli,
                                                buf, sizeof(buf), &len, ecjpake_lgc, NULL) == 0);

    TEST_ASSERT(mbedtls_ecjpake_read_round_one(&srv, buf, len) == 0);

    TEST_ASSERT(mbedtls_ecjpake_write_round_one(&srv,
                                                buf, sizeof(buf), &len, ecjpake_lgc, NULL) == 0);

    TEST_ASSERT(mbedtls_ecjpake_read_round_one(&cli, buf, len) == 0);

    TEST_ASSERT(mbedtls_ecjpake_write_round_two(&srv,
                                                buf, sizeof(buf), &len, ecjpake_lgc, NULL) == 0);

    TEST_ASSERT(mbedtls_ecjpake_read_round_two(&cli, buf, len) == 0);

    TEST_ASSERT(mbedtls_ecjpake_derive_secret(&cli,
                                              pms, sizeof(pms), &pmslen, ecjpake_lgc, NULL) == 0);

    TEST_ASSERT(mbedtls_ecjpake_write_round_two(&cli,
                                                buf, sizeof(buf), &len, ecjpake_lgc, NULL) == 0);

    TEST_ASSERT(mbedtls_ecjpake_read_round_two(&srv, buf, len) == 0);

    TEST_ASSERT(mbedtls_ecjpake_derive_secret(&srv,
                                              buf, sizeof(buf), &len, ecjpake_lgc, NULL) == 0);

    TEST_ASSERT(len == pmslen);
    TEST_ASSERT(memcmp(buf, pms, len) == 0);

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

#if !defined(MBEDTLS_ECJPAKE_ALT)
    /* 'reference handshake' tests can only be run against implementations
     * for which we have 100% control over how the random ephemeral keys
     * are generated. This is only the case for the internal Mbed TLS
     * implementation, so these tests are skipped in case the internal
     * implementation is swapped out for an alternative one. */
    if (verbose != 0) {
        mbedtls_printf("  ECJPAKE test #2 (reference handshake): ");
    }

    /* Simulate generation of round one */
    MBEDTLS_MPI_CHK(ecjpake_test_load(&cli,
                                      ecjpake_test_x1, sizeof(ecjpake_test_x1),
                                      ecjpake_test_x2, sizeof(ecjpake_test_x2)));

    MBEDTLS_MPI_CHK(ecjpake_test_load(&srv,
                                      ecjpake_test_x3, sizeof(ecjpake_test_x3),
                                      ecjpake_test_x4, sizeof(ecjpake_test_x4)));

    /* Read round one */
    TEST_ASSERT(mbedtls_ecjpake_read_round_one(&srv,
                                               ecjpake_test_cli_one,
                                               sizeof(ecjpake_test_cli_one)) == 0);

    TEST_ASSERT(mbedtls_ecjpake_read_round_one(&cli,
                                               ecjpake_test_srv_one,
                                               sizeof(ecjpake_test_srv_one)) == 0);

    /* Skip generation of round two, read round two */
    TEST_ASSERT(mbedtls_ecjpake_read_round_two(&cli,
                                               ecjpake_test_srv_two,
                                               sizeof(ecjpake_test_srv_two)) == 0);

    TEST_ASSERT(mbedtls_ecjpake_read_round_two(&srv,
                                               ecjpake_test_cli_two,
                                               sizeof(ecjpake_test_cli_two)) == 0);

    /* Server derives PMS */
    TEST_ASSERT(mbedtls_ecjpake_derive_secret(&srv,
                                              buf, sizeof(buf), &len, ecjpake_lgc, NULL) == 0);

    TEST_ASSERT(len == sizeof(ecjpake_test_pms));
    TEST_ASSERT(memcmp(buf, ecjpake_test_pms, len) == 0);

    /* Server derives K as unsigned binary data */
    TEST_ASSERT(mbedtls_ecjpake_write_shared_key(&srv,
                                                 buf, sizeof(buf), &len, ecjpake_lgc, NULL) == 0);

    TEST_ASSERT(len == sizeof(ecjpake_test_shared_key));
    TEST_ASSERT(memcmp(buf, ecjpake_test_shared_key, len) == 0);

    memset(buf, 0, len);   /* Avoid interferences with next step */

    /* Client derives PMS */
    TEST_ASSERT(mbedtls_ecjpake_derive_secret(&cli,
                                              buf, sizeof(buf), &len, ecjpake_lgc, NULL) == 0);

    TEST_ASSERT(len == sizeof(ecjpake_test_pms));
    TEST_ASSERT(memcmp(buf, ecjpake_test_pms, len) == 0);

    /* Client derives K as unsigned binary data */
    TEST_ASSERT(mbedtls_ecjpake_write_shared_key(&cli,
                                                 buf, sizeof(buf), &len, ecjpake_lgc, NULL) == 0);

    TEST_ASSERT(len == sizeof(ecjpake_test_shared_key));
    TEST_ASSERT(memcmp(buf, ecjpake_test_shared_key, len) == 0);

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }
#endif /* ! MBEDTLS_ECJPAKE_ALT */

cleanup:
    mbedtls_ecjpake_free(&cli);
    mbedtls_ecjpake_free(&srv);

    if (ret != 0) {
        if (verbose != 0) {
            mbedtls_printf("failed\n");
        }

        ret = 1;
    }

    if (verbose != 0) {
        mbedtls_printf("\n");
    }

    return ret;
}

#undef TEST_ASSERT

#endif /* MBEDTLS_ECP_DP_SECP256R1_ENABLED && MBEDTLS_MD_CAN_SHA256 */

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_ECJPAKE_C */
