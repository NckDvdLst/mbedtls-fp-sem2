/*
*  OQUAKE
 *
 *  Copyright Nick Leist
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(MBEDTLS_OQUAKE_C)

#include <string.h>
#include <stdlib.h>

#include "md_wrap.h"

#include "mbedtls/bignum.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/oquake.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"

#include "mlkem_native.h"
#include "mbedtls/error.h"
#include "src/poly.h"
#include "src/poly_k.h"

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

static void write_u32_be(uint8_t *dst, uint32_t v) {
    dst[0] = (v >> 24) & 0xFF;
    dst[1] = (v >> 16) & 0xFF;
    dst[2] = (v >>  8) & 0xFF;
    dst[3] =  v        & 0xFF;
}

/**
 * Turns sid into fullsid:
 * fullsid = len(sid)<32bit> || sid || len(u)<32bit> || u || len(s)<32bit> || s
 *
 * \param sid           Session ID to convert
 * \param sid_len       Length of session ID in bytes
 * \param u             Client's IPv6 Address
 * \param s             Server's IPv6 Address
 * \param encoded_sid   Output pointer for the byte array containing fullsid (the encoded sid)
 *
 * \return A byte array containing fullsid
 */
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

/**
 * @brief Extends two shared random strings to an extended sid
 *
 * @param md                    Message Digest Type to use for HKDF
 * @param s1                    Client random value
 * @param s2                    Server random value
 * @param[out] extended_sid     Output buffer for extended sid
 *
 * @return 0 if successful and a negative error code on failure
 */
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

/**
 * \brief           Creates init message of OQUAKE flow
 *
 * \param md        Message Digest Type to use for HKDF
 * \param prs       Password-related string
 * \param prs_len   Length of the password-related string
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG parameter to be passed to \p f_rng. This
 *                  may be \c NULL if \p f_rng doesn't use a context.
 *
 * \param[out] ctx   Will contain the opaque context to be stored by the initiator
 * \param[out] init_msg   Pointer to the message bytestring output of the function
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
static int mbedtls_oquake_init_step(const mbedtls_md_info_t *md,
                    unsigned char *prs, const size_t prs_len,
                    mbedtls_f_rng_t *f_rng, void *p_rng,
                    mbedtls_oquake_context *ctx, uint8_t **init_msg, size_t *msg_len) {

    int ret = MBEDTLS_ERR_ERROR_GENERIC_ERROR;

    // initialise buffer for seed
    uint8_t *seed = mbedtls_calloc(1, 2*MLKEM_SYMBYTES);
    
    // generate seed and keypair
    if (!seed) goto cleanup;
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
    *msg_len = sizeof(r) + sizeof(ek);
    uint8_t *message = mbedtls_calloc(1, *msg_len);
    if(!message) return -1;
    memcpy(message, r, sizeof(r));
    memcpy(message + sizeof(r), ek, sizeof(ek));
    *init_msg = message;
    
    // configure ctx
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->s, r, sizeof(r)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->t, ek, sizeof(ek)));
    ret = 0;

    cleanup:
    mbedtls_free(seed);
    return ret;

}


/**
 * \brief           Processes init message and creates response message of OQUAKE flow.
 *                  Computes also the shared secret.
 *
 * \param md        Message Digest Type to use for HKDF
 * \param prs       Password-related string
 * \param prs_len   Length of the password-related string
 *
 * \param[out] resp_msg Pointer to the message bytestring output of the function
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
static int mbedtls_oquake_respond(mbedtls_oquake_context *ctx,
                    const mbedtls_md_info_t *md,
                    const unsigned char *prs, const size_t prs_len,
                    uint8_t **resp_msg) {

    int ret = MBEDTLS_ERR_ERROR_GENERIC_ERROR;

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
    uint8_t *ikm    = mbedtls_calloc(1, ikm_len);
    if (!ikm) goto failure_cleanup_ikm; ;
    {
        uint8_t *p = ikm;
        memcpy(p, OQUAKE_DST,          OQUAKE_DST_LEN);          p += OQUAKE_DST_LEN;
        memcpy(p, LABEL_OQUAKE, LABEL_OQUAKE_LEN); p += LABEL_OQUAKE_LEN;
        memcpy(p, ctx->fullsid,      fullsid_len);              p += fullsid_len;
        memcpy(p, key,            sizeof(key));
    }

    // extract pseudo random key from input keying material
    uint8_t *prk = mbedtls_calloc(1, OQUAKE_SHA256_LEN);
    if (!prk) goto failure_cleanup_ikm;
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
    uint8_t *message = mbedtls_calloc(1, CRYPTO_CIPHERTEXTBYTES + sizeof(h));
    memcpy(message, ciphertext, CRYPTO_CIPHERTEXTBYTES);
    memcpy(message+CRYPTO_CIPHERTEXTBYTES, h, sizeof h);
    *resp_msg = message;

    ret = 0;

    failure_cleanup_ikm:
    mbedtls_free(ikm);
    cleanup:
    return ret;

}


/**
 * \brief           Processes response message and computes the shared secret
 *
 * \param ctx           OQUAKE initiator context
 *
 * \param[out] ss       Shared secret, byte string of 32 bytes
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
static int mbedtls_oquake_finish(const mbedtls_oquake_context *ctx, uint8_t *ss) {

    // compute shared secret using KDF
    uint8_t sk[OQUAKE_DST_LEN + 2];
    memcpy(sk,           OQUAKE_DST,         OQUAKE_DST_LEN);
    memcpy(sk + OQUAKE_DST_LEN, "sk",  2);
    const size_t sk_len = sizeof sk;
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(ctx->md_type);
    hkdf_expand_custom(md, ctx->prk, md->size, sk, sk_len, ss, 32);

    return 0;

}

#define ID_MINE     (oquake_id[ctx->role])
#define ID_PEER     (oquake_id[1 - ctx->role])


/*
 * Initialize context
 */
void mbedtls_oquake_init(mbedtls_oquake_context *ctx)
{
    ctx->md_type = MBEDTLS_MD_NONE;

    mbedtls_mpi_init(&ctx->sid_part);
    mbedtls_mpi_init(&ctx->s);
    mbedtls_mpi_init(&ctx->t);

    ctx->fullsid = NULL;
}

/*
 * Free context
 */
void mbedtls_oquake_free(mbedtls_oquake_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    ctx->md_type = MBEDTLS_MD_NONE;
    ctx->prs_len = 0;

    mbedtls_free(ctx->prs);
    mbedtls_mpi_free(&ctx->sid_part);
    mbedtls_free(ctx->fullsid);

    mbedtls_platform_zeroize(ctx->pk, MLKEM768_SECRETKEYBYTES);
    mbedtls_platform_zeroize(ctx->sk, MLKEM768_SECRETKEYBYTES);
    mbedtls_mpi_free(&ctx->s);
    mbedtls_mpi_free(&ctx->t);

}

/*
 * Setup context
 */
int mbedtls_oquake_setup(mbedtls_oquake_context *ctx,
                          mbedtls_oquake_role role,
                          mbedtls_md_type_t hash,
                          const unsigned char *secret,
                          size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (role != MBEDTLS_OQUAKE_INITIATOR && role != MBEDTLS_OQUAKE_RESPONDER) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA ;
    }

    ctx->role = role;

    if ((mbedtls_md_info_from_type(hash)) == NULL) {
        return MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
    }

    ctx->md_type = hash;

    ctx->prs = mbedtls_calloc(1, len);
    if (!ctx->prs) {
        ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
        goto cleanup;
    }
    memcpy(ctx->prs, secret, len);
    ctx->prs_len = len;

    ret = 0;

cleanup:
    if (ret != 0) {
        mbedtls_oquake_free(ctx);
    }

    return ret;
}

/*
 * Check if context is ready for use
 */
int mbedtls_oquake_check(const mbedtls_oquake_context *ctx)
{
    if (ctx->md_type == MBEDTLS_MD_NONE ||
        ctx->prs == NULL) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    return 0;
}

/*
 * Read and process the first round message
 */
int mbedtls_oquake_read_round_one(mbedtls_oquake_context *ctx,
                                   const unsigned char *buf,
                                   size_t len)
{
    if (ctx->role == MBEDTLS_OQUAKE_RESPONDER) {
        /* responder starts by reading the initiator's sid part
         * (then acts as OQUAKE Client when writing round one
         * and starts regular OQUAKE communication)
         */

        if (len != 32) {
            return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        }

        return mbedtls_mpi_read_binary(&ctx->sid_part, buf, len);

    } else if (ctx->role == MBEDTLS_OQUAKE_INITIATOR) {
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
int mbedtls_oquake_write_round_one(mbedtls_oquake_context *ctx,
                                    unsigned char *buf, size_t len, size_t *olen,
                                    mbedtls_f_rng_t *f_rng,
                                    void *p_rng) {

    if (ctx->role == MBEDTLS_OQUAKE_INITIATOR) {
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

    } else if (ctx->role == MBEDTLS_OQUAKE_RESPONDER) {

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

/*
 * Read and process second round message
 */
int mbedtls_oquake_read_round_two(mbedtls_oquake_context *ctx,
                                   const unsigned char *buf,
                                   size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (ctx->role == MBEDTLS_OQUAKE_RESPONDER) {

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
    } else if (ctx->role == MBEDTLS_OQUAKE_INITIATOR) {
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

/*
 * Generate and write the second round message (S: 7.4.2.5, C: 7.4.2.6)
 */
int mbedtls_oquake_write_round_two(mbedtls_oquake_context *ctx,
                                    unsigned char *buf, size_t len, size_t *olen,
                                    int (*f_rng)(void *, unsigned char *, size_t),
                                    void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    uint8_t *msg = NULL;

    if (ctx->role == MBEDTLS_OQUAKE_RESPONDER) {

        // generate init message by performing OQUAKE.INIT step
        size_t msg_len;
        if (mbedtls_oquake_init_step(mbedtls_md_info_from_type(ctx->md_type),
            ctx->prs, ctx->prs_len, f_rng, p_rng, ctx, &msg, &msg_len))
        {
            goto cleanup;
        }

        // write init msg to buf
        if (len < msg_len) {
            ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
            goto cleanup;
        }

        memcpy(buf, msg, msg_len);
        *olen = msg_len;

    } else if (ctx->role == MBEDTLS_OQUAKE_INITIATOR) {
        *olen = CRYPTO_CIPHERTEXTBYTES + 64;
        if (len < *olen) {
            ret = MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
            goto cleanup;
        }

        mbedtls_oquake_respond(ctx, mbedtls_md_info_from_type(ctx->md_type),
            ctx->prs, ctx->prs_len, &msg);

        memcpy(buf, msg, *olen);
    } else {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }
    ret = 0;

cleanup:
    mbedtls_free(msg);
    return ret;
}

int mbedtls_oquake_derive_secret(mbedtls_oquake_context *ctx,
                                  unsigned char *buf, size_t len, size_t *olen)
{
    int ret = MBEDTLS_ERR_ERROR_GENERIC_ERROR;

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


#if defined(MBEDTLS_SELF_TEST)

#if !defined(MBEDTLS_MD_CAN_SHA256)
int mbedtls_oquake_self_test(int verbose)
{
    (void) verbose;
    return 0;
}
#else

static const unsigned char oquake_test_password[] = {
    0x74, 0x68, 0x72, 0x65, 0x61, 0x64, 0x6a, 0x70, 0x61, 0x6b, 0x65, 0x74,
    0x65, 0x73, 0x74
};

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
int mbedtls_oquake_self_test(int verbose)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_oquake_context cli;
    mbedtls_oquake_context srv;
    unsigned char buf[1512], pms[32];
    size_t len, pmslen;

    mbedtls_oquake_init(&cli);
    mbedtls_oquake_init(&srv);

    if (verbose != 0) {
        mbedtls_printf("  OQUAKE test #0 (setup): ");
    }

    TEST_ASSERT(mbedtls_oquake_setup(&cli, MBEDTLS_OQUAKE_INITIATOR,
                                      MBEDTLS_MD_SHA256,
                                      oquake_test_password,
                                      sizeof(oquake_test_password)) == 0);

    TEST_ASSERT(mbedtls_oquake_setup(&srv, MBEDTLS_OQUAKE_RESPONDER,
                                      MBEDTLS_MD_SHA256,
                                      oquake_test_password,
                                      sizeof(oquake_test_password)) == 0);

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

    if (verbose != 0) {
        mbedtls_printf("  OQUAKE test #1 (random handshake): ");
    }

    TEST_ASSERT(mbedtls_oquake_write_round_one(&cli,
                                                buf, sizeof(buf), &len, ecjpake_lgc, NULL) == 0);

    TEST_ASSERT(mbedtls_oquake_read_round_one(&srv, buf, len) == 0);

    TEST_ASSERT(mbedtls_oquake_write_round_one(&srv,
                                                buf, sizeof(buf), &len, ecjpake_lgc, NULL) == 0);

    TEST_ASSERT(mbedtls_oquake_read_round_one(&cli, buf, len) == 0);

    TEST_ASSERT(mbedtls_oquake_write_round_two(&srv,
                                                buf, sizeof(buf), &len, ecjpake_lgc, NULL) == 0);

    TEST_ASSERT(mbedtls_oquake_read_round_two(&cli, buf, len) == 0);

    TEST_ASSERT(mbedtls_oquake_write_round_two(&cli,
                                                buf, sizeof(buf), &len, ecjpake_lgc, NULL) == 0);

    TEST_ASSERT(mbedtls_oquake_derive_secret(&cli,
                                              pms, sizeof(pms), &pmslen) == 0);

    TEST_ASSERT(mbedtls_oquake_read_round_two(&srv, buf, len) == 0);

    TEST_ASSERT(mbedtls_oquake_derive_secret(&srv,
                                              buf, sizeof(buf), &len) == 0);

    TEST_ASSERT(len == pmslen);
    TEST_ASSERT(memcmp(buf, pms, len) == 0);

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }


cleanup:
    mbedtls_oquake_free(&cli);
    mbedtls_oquake_free(&srv);

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

#endif