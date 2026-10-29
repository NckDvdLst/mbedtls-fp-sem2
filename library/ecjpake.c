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
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

#include "md_wrap.h"

#if !defined(MBEDTLS_ECJPAKE_ALT)

#define ID_MINE     (ecjpake_id[ctx->role])
#define ID_PEER     (ecjpake_id[1 - ctx->role])

/*
 * Initialize context
 */
void mbedtls_ecjpake_init(mbedtls_ecjpake_context *ctx)
{
    ctx->md_type = MBEDTLS_MD_NONE;
    ctx->point_format = MBEDTLS_ECP_PF_UNCOMPRESSED;

    mbedtls_ecp_point_init(&ctx->Xm1);

    mbedtls_mpi_init(&ctx->xm1);
    mbedtls_mpi_init(&ctx->xm2);
    mbedtls_mpi_init(&ctx->s);

    mbedtls_cpace_init(&ctx->cpace);
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
    mbedtls_mpi_free(&ctx->xm2);
    mbedtls_mpi_free(&ctx->s);

    mbedtls_zeroize_and_free(ctx->prs, ctx->prs_len);
    ctx->prs_len = 0;
    mbedtls_cpace_free(&ctx->cpace);
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

    if (role != MBEDTLS_ECJPAKE_CLIENT && role != MBEDTLS_ECJPAKE_SERVER) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    ctx->role = role;

    if ((mbedtls_md_info_from_type(hash)) == NULL) {
        return MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
    }

    ctx->md_type = hash;

    (void)curve;

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->s, secret, len));

    ctx->prs = mbedtls_calloc(1, len);
    if (! ctx->prs) {
        ret = MBEDTLS_ERR_CPACEOQUAKE_ALLOC_FAILED;
        goto cleanup;
    }
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
    switch (point_format) {
        case MBEDTLS_ECP_PF_UNCOMPRESSED:
        case MBEDTLS_ECP_PF_COMPRESSED:
            ctx->point_format = point_format;
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
 * Read and process the first round message
 */
int mbedtls_ecjpake_read_round_one(mbedtls_ecjpake_context *ctx,
                                   const unsigned char *buf,
                                   size_t len)
{
    int ret = 0;

    if (ctx->role == MBEDTLS_ECJPAKE_SERVER) {
        /* Read Init Msg from Client (s1 || cpace.init_msg) */

        if (len < MBEDTLS_CPACEOQUAKE_SID_LEN) {
            ret = MBEDTLS_ERR_CPACEOQUAKE_CORRUPT_MSG;
            goto cleanup;
        }

        // read peer's sid part
        memcpy(ctx->s1, buf, MBEDTLS_CPACEOQUAKE_SID_LEN);

        // set up cpace ctx, read Ya and save it to ctx
        if ((ret = mbedtls_cpace_setup(&ctx->cpace,
            MBEDTLS_CPACE_RESPONDER,
            MBEDTLS_CPACE_P256_XMD_SHA_256_SSWU_NU_SHA256,
            (unsigned char *)MBEDTLS_CPACEOQUAKE_U_IDENTIFIER, sizeof(MBEDTLS_CPACEOQUAKE_U_IDENTIFIER)-1,
            (unsigned char *)MBEDTLS_CPACEOQUAKE_S_IDENTIFIER, sizeof(MBEDTLS_CPACEOQUAKE_S_IDENTIFIER)-1,
            ctx->s1, MBEDTLS_CPACEOQUAKE_SID_LEN,
            ctx->prs, ctx->prs_len)) != 0) goto cleanup;
        ctx->msg1_len = len - MBEDTLS_CPACEOQUAKE_SID_LEN;
        memcpy(&ctx->msg1, buf+MBEDTLS_CPACEOQUAKE_SID_LEN, ctx->msg1_len);
    } else if (ctx->role == MBEDTLS_ECJPAKE_CLIENT) {
        /* Read Response Msg from Server
         * (cpace.resp_msg) */

        // get msg2 and msg3 from buf
        ctx->msg2_len = len;
        memcpy(ctx->msg2, buf, ctx->msg2_len);

    }

    cleanup:

    return ret;
}


/*
 * Generate and write the first round message
 */
int mbedtls_ecjpake_write_round_one(mbedtls_ecjpake_context *ctx,
                                    unsigned char *buf, size_t len, size_t *olen,
                                    int (*f_rng)(void *, unsigned char *, size_t),
                                    void *p_rng)
{
    int ret = 0;

    // Ya CPace public key of Initiator, needed by server
    mbedtls_ecp_point Ya;
    mbedtls_ecp_point_init(&Ya);

    if (ctx->role == MBEDTLS_ECJPAKE_CLIENT) {
        /* This represents the CPace.Init procedure */

        // first generate s1. We use it as cpace-sid
        f_rng(p_rng, ctx->s1, MBEDTLS_CPACEOQUAKE_SID_LEN);
        memcpy(buf, &ctx->s1, MBEDTLS_CPACEOQUAKE_SID_LEN);
        *olen = MBEDTLS_CPACEOQUAKE_SID_LEN;

        // initialise cpace context and perform init step
        if ((ret = mbedtls_cpace_setup(&ctx->cpace,
            MBEDTLS_CPACE_INITIATOR,
            MBEDTLS_CPACE_P256_XMD_SHA_256_SSWU_NU_SHA256,
            (unsigned char *)MBEDTLS_CPACEOQUAKE_U_IDENTIFIER, sizeof(MBEDTLS_CPACEOQUAKE_U_IDENTIFIER)-1,
            (unsigned char *)MBEDTLS_CPACEOQUAKE_S_IDENTIFIER, sizeof(MBEDTLS_CPACEOQUAKE_S_IDENTIFIER)-1,
            ctx->s1, MBEDTLS_CPACEOQUAKE_SID_LEN,
            ctx->prs, ctx->prs_len)) != 0) goto cleanup;
        if ((ret = mbedtls_cpace_step_init(&ctx->cpace, f_rng, p_rng)) != 0) goto cleanup;

        // serialise CPace.Init msg (= Ya = ctx->cpace.Y), and concat it to buf
        unsigned char serialised_Ya[MBEDTLS_ECP_MAX_PT_LEN];
        size_t serialised_Ya_len;
        MBEDTLS_MPI_CHK(mbedtls_ecp_point_write_binary(&ctx->cpace.cs.h2c_cipher_suite.ecp_group, &ctx->cpace.Y,
            MBEDTLS_ECP_PF_UNCOMPRESSED, &serialised_Ya_len, serialised_Ya, sizeof(serialised_Ya)));
        *olen += serialised_Ya_len;
        if (*olen > len) {
            ret = MBEDTLS_ERR_CPACEOQUAKE_BUFFER_TOO_SMALL;
            goto cleanup;
        }
        memcpy(buf + MBEDTLS_CPACEOQUAKE_SID_LEN, serialised_Ya, serialised_Ya_len);
        memcpy(ctx->msg1, serialised_Ya, serialised_Ya_len);
        ctx->msg1_len = serialised_Ya_len;
    } else if (ctx->role == MBEDTLS_ECJPAKE_SERVER) {
        /* This represents the CPace.Respond procedure */

        // deserialise Ya from msg1
        mbedtls_ecp_point_read_binary(&ctx->cpace.cs.h2c_cipher_suite.ecp_group,
            &Ya, ctx->msg1, ctx->msg1_len);

        // perform CPace.Respond step
        if ((ret = mbedtls_cpace_step_respond(&ctx->cpace, &Ya, ctx->ISK, f_rng, p_rng)) != 0)
            goto cleanup;

        // store msg2 from CPace Result
        mbedtls_ecp_point_write_binary(&ctx->cpace.cs.h2c_cipher_suite.ecp_group,
            &ctx->cpace.Y, MBEDTLS_ECP_PF_UNCOMPRESSED, &ctx->msg2_len,
            ctx->msg2, sizeof(ctx->msg2));

        {
            *olen = ctx->msg2_len;
            if (*olen > len) {
                ret = MBEDTLS_ERR_CPACEOQUAKE_BUFFER_TOO_SMALL;
                goto cleanup;
            }
            memcpy(buf, ctx->msg2, ctx->msg2_len);
        }

    }

    cleanup:
    mbedtls_ecp_point_free(&Ya);
    return ret;
}

/*
 * Read and process second round message (C: 7.4.2.5, S: 7.4.2.6)
 */
int mbedtls_ecjpake_read_round_two(mbedtls_ecjpake_context *ctx,
                                   const unsigned char *buf,
                                   size_t len)
{
    int ret = 0;
    (void)ctx;
    (void)buf;
    (void)len;

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
    int ret = 0;

    mbedtls_ecp_point Yb;
    mbedtls_ecp_point_init(&Yb);

    // The client has to perform the finish step to store the secret in ctx->ISK
    if (ctx->role == MBEDTLS_ECJPAKE_CLIENT)
    {
        if ((ret = mbedtls_ecp_point_read_binary(&ctx->cpace.cs.h2c_cipher_suite.ecp_group,
                &Yb, ctx->msg2, ctx->msg2_len)) != 0) goto cleanup;

        if ((ret = mbedtls_cpace_step_finish(&ctx->cpace, &Yb, ctx->ISK, f_rng, p_rng)) != 0) goto cleanup;

    }

    // Message 2 always empty
    memset(buf, 0, len);
    *olen = 1;

    cleanup:
    mbedtls_ecp_point_free(&Yb);

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

int mbedtls_ecjpake_derive_secret(mbedtls_ecjpake_context *ctx,
                                  unsigned char *buf, size_t len, size_t *olen
                                  )
{
    int ret = 0;

    *olen = mbedtls_md_info_from_type(ctx->cpace.cs.md_type)->size;

    if (len < *olen) {
        ret = MBEDTLS_ERR_CPACEOQUAKE_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    memcpy(buf, ctx->ISK, *olen);

    *olen = MBEDTLS_CPACEOQUAKE_NKEY;

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
    (void)olen;

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

    unsigned char buf[2048];
    size_t len;
    unsigned char secret_c[MBEDTLS_CPACEOQUAKE_NKEY];
    size_t secret_c_len;
    unsigned char secret_s[MBEDTLS_CPACEOQUAKE_NKEY];
    size_t secret_s_len;

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

    TEST_ASSERT(mbedtls_ecjpake_write_round_two(&cli,
                                                buf, sizeof(buf), &len, ecjpake_lgc, NULL) == 0);

    TEST_ASSERT(mbedtls_ecjpake_derive_secret(&cli,
                                              secret_c, sizeof(secret_c), &secret_c_len) == 0);

    TEST_ASSERT(mbedtls_ecjpake_read_round_two(&srv, buf, len) == 0);

    TEST_ASSERT(mbedtls_ecjpake_derive_secret(&srv,
                                              secret_s, sizeof(secret_s), &secret_s_len) == 0);

    TEST_ASSERT(secret_c_len == secret_s_len);
    TEST_ASSERT(memcmp(secret_c, secret_s, secret_c_len) == 0);

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

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
