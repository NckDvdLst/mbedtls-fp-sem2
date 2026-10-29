
#include "common.h"

#if defined(MBEDTLS_ECJPAKE_C)

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

#if !defined(MBEDTLS_ECJPAKE_ALT)

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * STATIC FUNCTIONS
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 */

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

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * MAIN FUNCTIONS
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 */

void mbedtls_oquake_free(mbedtls_oquake_context *ctx) {
    mbedtls_zeroize_and_free(ctx->prs, ctx->prs_len);
    mbedtls_zeroize_and_free(ctx->fullsid, ctx->fullsid_len);
}

int mbedtls_oquake_setup(mbedtls_oquake_context *ctx,
    mbedtls_md_type_t md_type,
    unsigned char *prs, size_t prs_len,
    unsigned char *fullsid, size_t fullsid_len
    ) {
    int ret = 0;

    ctx->md_type = md_type;
    ctx->prs = mbedtls_calloc(1, prs_len);
    if (!ctx->prs) {
        ret = MBEDTLS_ERR_OQUAKE_ALLOC_FAILED;
        goto cleanup;
    }
    memcpy(ctx->prs, prs, prs_len);
    ctx->prs_len = prs_len;
    ctx->fullsid = mbedtls_calloc(1, fullsid_len);
    if (!ctx->fullsid) {
        ret = MBEDTLS_ERR_OQUAKE_ALLOC_FAILED;
        goto cleanup;
    }
    memcpy(ctx->fullsid, fullsid, fullsid_len);
    ctx->fullsid_len = fullsid_len;

    return 0;

    cleanup:
    mbedtls_oquake_free(ctx);

    return ret;
}

int mbedtls_oquake_step_init(mbedtls_oquake_context *ctx, uint8_t *init_msg,
                    mbedtls_f_rng_t *f_rng, void *p_rng) {

    int ret = MBEDTLS_ERR_ERROR_GENERIC_ERROR;

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(ctx->md_type);

    // initialise buffer for seed
    unsigned char seed[2*MLKEM_SYMBYTES];

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
    compute_t_pad(md, ctx->prs, ctx->prs_len, ctx->fullsid, ctx->fullsid_len, r, T_pad);
    xor_inplace(ek, T_pad, sizeof T_pad);

    // mask randomness r using masked ek
    uint8_t s_pad[3*OQUAKE_NSEC];
    compute_s_pad(md, ctx->prs, ctx->prs_len, ctx->fullsid, ctx->fullsid_len, ek, s_pad);
    xor_inplace(r, s_pad, sizeof s_pad);

    // init_msg: r || ek
    memcpy(init_msg, r, sizeof(r));
    memcpy(init_msg + sizeof(r), ek, sizeof(ek));

    ret = 0;

    cleanup:

    return ret;

}

int mbedtls_oquake_step_respond(mbedtls_oquake_context *ctx,
                    const unsigned char *init_msg, size_t init_msg_len,
                    uint8_t *resp_msg, unsigned char *ss) {

    int ret = MBEDTLS_ERR_ERROR_GENERIC_ERROR;

    // buffer for IKM for HKDF, allocated later
    unsigned char *ikm = NULL;

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(ctx->md_type);

    /*
     * first process init_msg and copy information to context
     */
    if (init_msg_len < 3*OQUAKE_NSEC + KEMELEON_EKBYTES)
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;

    if (md->size != OQUAKE_SHA256_LEN) return ret;

    // read masked random and masked ek from ctx
    const size_t fullsid_len = ctx->fullsid_len;

    uint8_t msg_s[3*OQUAKE_NSEC];
    memcpy(&msg_s, init_msg, 3*OQUAKE_NSEC);
    uint8_t ek[KEMELEON_EKBYTES];
    memcpy(&ek, init_msg + 3*OQUAKE_NSEC, KEMELEON_EKBYTES);

    // reconstruct random and ek from masked values
    uint8_t s_pad[3*OQUAKE_NSEC];
    compute_s_pad(md, ctx->prs, ctx->prs_len, ctx->fullsid, fullsid_len, ek, s_pad);
    xor_inplace(msg_s, s_pad, sizeof s_pad);
    uint8_t T_pad[KEMELEON_EKBYTES];
    compute_t_pad(md, ctx->prs, ctx->prs_len, ctx->fullsid, fullsid_len, msg_s, T_pad);
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
    if (!ikm) goto cleanup;
    {
        uint8_t *p = ikm;
        memcpy(p, OQUAKE_DST,          OQUAKE_DST_LEN);          p += OQUAKE_DST_LEN;
        memcpy(p, LABEL_OQUAKE, LABEL_OQUAKE_LEN); p += LABEL_OQUAKE_LEN;
        memcpy(p, ctx->fullsid,      fullsid_len);              p += fullsid_len;
        memcpy(p, key,            sizeof(key));
    }

    // extract pseudo random key from input keying material
    unsigned char prk[OQUAKE_SHA256_LEN];
    uint8_t h[MBEDTLS_OQUAKE_NKC];
    hkdf_extract_custom(md, ctx->prs, ctx->prs_len, ikm, ikm_len, prk);

    // expand prk to get confirmation value h
    uint8_t confirm[OQUAKE_DST_LEN + 7];
    memcpy(confirm,           OQUAKE_DST,         OQUAKE_DST_LEN);
    memcpy(confirm + OQUAKE_DST_LEN, "confirm",  7);
    const size_t confirm_len = sizeof confirm;
    hkdf_expand_custom(md, prk, md->size, confirm, confirm_len, h, sizeof h);

    // compute shared secret using KDF
    uint8_t sk[OQUAKE_DST_LEN + 2];
    memcpy(sk,           OQUAKE_DST,         OQUAKE_DST_LEN);
    memcpy(sk + OQUAKE_DST_LEN, "sk",  2);
    const size_t sk_len = sizeof sk;
    hkdf_expand_custom(md, prk, md->size, sk, sk_len, ss, 32);

    // build response message
    memcpy(resp_msg, ciphertext, CRYPTO_CIPHERTEXTBYTES);
    memcpy(resp_msg+CRYPTO_CIPHERTEXTBYTES, h, sizeof h);

    ret = 0;

    cleanup:
    mbedtls_free(ikm);
    return ret;

}

int mbedtls_oquake_step_finish(
    const mbedtls_oquake_context *ctx,
    const unsigned char *resp_msg, size_t resp_msg_len,
    uint8_t *ss) {
    int ret = 0;

    uint8_t verifier[64];
    size_t hash_len = 64;
    uint8_t key[32];

    // buffer for IKM for HKDF, allocated later
    unsigned char *ikm = NULL;

    if (resp_msg_len < CRYPTO_CIPHERTEXTBYTES + sizeof(verifier))
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;

    // get ciphertext from resp_msg and decapsulate the shared key
    uint8_t ciphertext[CRYPTO_CIPHERTEXTBYTES];
    memcpy(ciphertext, resp_msg, CRYPTO_CIPHERTEXTBYTES);
    if (crypto_kem_dec(key, ciphertext, ctx->sk)) return -1;

    // prepare shared secret computation
    const size_t  ikm_len = OQUAKE_DST_LEN + LABEL_OQUAKE_LEN + ctx->fullsid_len + sizeof(key);
    ikm    = mbedtls_calloc(1, ikm_len);
    if (!ikm) return -1;

    {
        uint8_t *p = ikm;
        memcpy(p, OQUAKE_DST,          OQUAKE_DST_LEN);          p += OQUAKE_DST_LEN;
        memcpy(p, LABEL_OQUAKE, LABEL_OQUAKE_LEN); p += LABEL_OQUAKE_LEN;
        memcpy(p, ctx->fullsid, ctx->fullsid_len);       p += ctx->fullsid_len;
        memcpy(p, key,            sizeof(key));
    }

    // compute prk
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(ctx->md_type);
    unsigned char prk[MBEDTLS_MD_MAX_SIZE];
    hkdf_extract_custom(md, ctx->prs, ctx->prs_len,
        ikm, ikm_len, prk);

    // compute confirmation value h
    uint8_t confirm[OQUAKE_DST_LEN + 7];
    memcpy(confirm,           OQUAKE_DST,         OQUAKE_DST_LEN);
    memcpy(confirm + OQUAKE_DST_LEN, "confirm",  7);
    const size_t confirm_len = sizeof confirm;
    hkdf_expand_custom(md, prk, md->size, confirm, confirm_len, verifier, sizeof verifier);

    if (memcmp_const(verifier, resp_msg + CRYPTO_CIPHERTEXTBYTES, hash_len)) {
        ret = -1;
        goto cleanup;
    }

    // compute shared secret using KDF
    uint8_t sk[OQUAKE_DST_LEN + 2];
    memcpy(sk,           OQUAKE_DST,         OQUAKE_DST_LEN);
    memcpy(sk + OQUAKE_DST_LEN, "sk",  2);
    const size_t sk_len = sizeof sk;
    hkdf_expand_custom(md, prk, md->size, sk, sk_len, ss, 32);

    cleanup:
    mbedtls_free(ikm);

    return ret;

}

#endif

#if defined(MBEDTLS_SELF_TEST)

static const unsigned char mbedtls_oquake_ss_test_prs[] = "Password";
static const unsigned char mbedtls_oquake_ss_test_sid[] = {
    0x34, 0xb3, 0x64, 0x54, 0xca, 0xb2, 0xe7, 0x84,
    0x2c, 0x38, 0x9f, 0x7d, 0x88, 0xec, 0xb7, 0xdf
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

int mbedtls_oquake_self_test(int verbose) {
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /*
     * Test prepend_len first
     */

    if (verbose != 0) {
        mbedtls_printf("  OQUAKE test #0 (check shared secret match): ");
    }

    mbedtls_oquake_context i_ctx;
    if (mbedtls_oquake_setup(&i_ctx, MBEDTLS_MD_SHA256,
        (unsigned char *)mbedtls_oquake_ss_test_prs, sizeof(mbedtls_oquake_ss_test_prs)-1,
        (unsigned char *)mbedtls_oquake_ss_test_sid, sizeof(mbedtls_oquake_ss_test_sid)) != 0)
        goto cleanup;

    mbedtls_oquake_context r_ctx;
    if (mbedtls_oquake_setup(&r_ctx, MBEDTLS_MD_SHA256,
        (unsigned char *)mbedtls_oquake_ss_test_prs, sizeof(mbedtls_oquake_ss_test_prs)-1,
        (unsigned char *)mbedtls_oquake_ss_test_sid, sizeof(mbedtls_oquake_ss_test_sid)) != 0)
        goto cleanup;

    unsigned char init_msg[3*OQUAKE_NSEC+KEMELEON_EKBYTES];
    size_t init_msg_len = sizeof(init_msg);
    mbedtls_oquake_step_init(&i_ctx, init_msg, self_test_rng, NULL);

    unsigned char resp_msg[CRYPTO_CIPHERTEXTBYTES+64];
    size_t resp_msg_len = sizeof(resp_msg);
    unsigned char ss_r[32];
    mbedtls_oquake_step_respond(&r_ctx, init_msg, init_msg_len, resp_msg, ss_r);

    unsigned char ss_i[32];
    mbedtls_oquake_step_finish(&i_ctx, resp_msg, resp_msg_len, ss_i);

    if (memcmp(ss_i, ss_r, 32) != 0) {
        goto cleanup;
    }

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

    ret = 0;

    cleanup:
    mbedtls_oquake_free(&r_ctx);
    mbedtls_oquake_free(&i_ctx);

    return ret;
}

#endif

#endif