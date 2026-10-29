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
    mbedtls_oquake_free(&ctx->oquake);
    mbedtls_platform_zeroize(&ctx->key1B, MBEDTLS_CPACEOQUAKE_SID_LEN);
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

static int lv_encode(const uint8_t *msg, const size_t msg_len, uint8_t *out) {
    memcpy(out + 2, msg, msg_len);
    out[0] = (msg_len >> 8) & 0xFF;
    out[1] = msg_len & 0xFF;
    return 0;
}

static int lv32_encode(const uint8_t *msg, const size_t msg_len, uint8_t *out) {
    memcpy(out + 4, msg, msg_len);
    out[0] = (msg_len >> 24) & 0xFF;
    out[1] = (msg_len >> 16) & 0xFF;
    out[2] = (msg_len >> 8) & 0xFF;
    out[3] = msg_len & 0xFF;
    return 0;
}

static size_t lv_decode(uint8_t *msg) {
    const size_t msg_len = (msg[0] << 8) | msg[1];
    memmove(msg, msg + 2, msg_len);
    return msg_len;
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
    const unsigned char s1[MBEDTLS_CPACEOQUAKE_SID_LEN],
    const unsigned char s2[MBEDTLS_CPACEOQUAKE_SID_LEN],
    unsigned char extended_sid[MBEDTLS_CPACEOQUAKE_SID_LEN]) {
    unsigned char s_concat[2*MBEDTLS_CPACEOQUAKE_SID_LEN];
    memcpy(s_concat, s1, MBEDTLS_CPACEOQUAKE_SID_LEN);
    memcpy(s_concat + MBEDTLS_CPACEOQUAKE_SID_LEN, s2, MBEDTLS_CPACEOQUAKE_SID_LEN);

    if (mbedtls_hkdf(md,
    (const unsigned char *)MBEDTLS_CPACEOQUAKE_DST "CPaceOQUAKE", sizeof(MBEDTLS_CPACEOQUAKE_DST "CPaceOQUAKE")-1,
    s_concat, sizeof(s_concat), (const unsigned char *)MBEDTLS_CPACEOQUAKE_DST "SID",
    sizeof(MBEDTLS_CPACEOQUAKE_DST "SID")-1,
    extended_sid, MBEDTLS_CPACEOQUAKE_SID_LEN))
        return -1;
    return 0;
}

/**
 * Turns sid into fullsid:
 * fullsid = len(sid)<32bit> || sid || len(u)<32bit> || u || len(s)<32bit> || s
 *
 * \param sid           Session ID to convert
 * \param sid_len       Length of session ID in bytes
 * \param u             Client's Identifier
 * \param u_len         Length of \p u
 * \param s             Server's Identifier
 * \param s_len         Length of \p s
 * \param[out] fullsid  The buffer the fullsid is written to. Must be at least
 *                      (\p sid_len + \p u_len + \p s_len + 12) Bytes long
 *
 * \return A byte array containing fullsid
 */
static void encode_sid(const uint8_t *sid, const size_t sid_len,
    const uint8_t *u, size_t u_len,
    const uint8_t *s, size_t s_len,
    unsigned char *fullsid) {
    unsigned char *ptr = fullsid;
    lv32_encode(sid, sid_len, ptr); ptr+=sid_len+4;
    lv32_encode(u, u_len, ptr); ptr += u_len+4;
    lv32_encode(s, s_len, ptr);
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
        /* Read Init Msg from Client (s1 || lv_encode(cpace.init_msg)) */

        if (len < MBEDTLS_CPACEOQUAKE_SID_LEN) {
            ret = MBEDTLS_ERR_CPACEOQUAKE_CORRUPT_MSG;
            goto cleanup;
        }

        // read peer's sid part
        memcpy(ctx->s1, buf, MBEDTLS_CPACEOQUAKE_SID_LEN);

        // set up cpace ctx, lv_decode Ya and save it to ctx
        if ((ret = mbedtls_cpace_setup(&ctx->cpace,
            MBEDTLS_CPACE_RESPONDER,
            MBEDTLS_CPACE_P256_XMD_SHA_256_SSWU_NU_SHA256,
            (unsigned char *)MBEDTLS_CPACEOQUAKE_U_IDENTIFIER, sizeof(MBEDTLS_CPACEOQUAKE_U_IDENTIFIER)-1,
            (unsigned char *)MBEDTLS_CPACEOQUAKE_S_IDENTIFIER, sizeof(MBEDTLS_CPACEOQUAKE_S_IDENTIFIER)-1,
            ctx->s1, MBEDTLS_CPACEOQUAKE_SID_LEN,
            ctx->prs, ctx->prs_len)) != 0) goto cleanup;
        ctx->msg1_len = lv_decode((unsigned char *)buf+MBEDTLS_CPACEOQUAKE_SID_LEN);
        memcpy(&ctx->msg1, buf+MBEDTLS_CPACEOQUAKE_SID_LEN, ctx->msg1_len);
    } else if (ctx->role == MBEDTLS_ECJPAKE_CLIENT) {
        /* Read Response Msg from Server
         * (s2 || lv_encode(cpace.resp_msg) || lv_encode(oquake.init_msg)) */

        if (len < MBEDTLS_CPACEOQUAKE_SID_LEN) {
            ret = MBEDTLS_ERR_CPACEOQUAKE_CORRUPT_MSG;
            goto cleanup;
        }

        // read peer's sid part
        memcpy(ctx->s2, buf, MBEDTLS_CPACEOQUAKE_SID_LEN);

        // construct  and store fullsid
        unsigned char extended_sid[MBEDTLS_CPACEOQUAKE_SID_LEN];
        if ((ret = extend_sid_of_two(mbedtls_md_info_from_type(ctx->md_type),
            ctx->s1, ctx->s2, extended_sid)) != 0) goto cleanup;
        encode_sid(extended_sid, MBEDTLS_CPACEOQUAKE_SID_LEN,
            (unsigned char *)MBEDTLS_CPACEOQUAKE_U_IDENTIFIER, sizeof(MBEDTLS_CPACEOQUAKE_U_IDENTIFIER)-1,
            (unsigned char *)MBEDTLS_CPACEOQUAKE_S_IDENTIFIER, sizeof(MBEDTLS_CPACEOQUAKE_S_IDENTIFIER)-1,
            ctx->fullsid);
        ctx->fullsid_real_len = MBEDTLS_CPACEOQUAKE_SID_LEN + 12 +
            sizeof(MBEDTLS_CPACEOQUAKE_U_IDENTIFIER)-1 +
                sizeof(MBEDTLS_CPACEOQUAKE_S_IDENTIFIER)-1;

        // get msg2 and msg3 from buf
        ctx->msg2_len = lv_decode((unsigned char *)buf+MBEDTLS_CPACEOQUAKE_SID_LEN);
        lv_decode((unsigned char *)buf+MBEDTLS_CPACEOQUAKE_SID_LEN+ctx->msg2_len+2);
        memcpy(ctx->msg2, buf+MBEDTLS_CPACEOQUAKE_SID_LEN, ctx->msg2_len);
        memcpy(ctx->msg3, buf+MBEDTLS_CPACEOQUAKE_SID_LEN+ctx->msg2_len+2, sizeof(ctx->msg3));

    }

    cleanup:

    return ret;
}

/**
 * @brief   Derives two keys, key1A and key1B from CPace-Shared Key key1 as specified in CPaceOQUAKE
 *
 * @param md            Message Digest Type to use for HKDF
 * @param key1          CPace ISK to derive key1A and key1B from
 * @param[out] key1A    Derived key1A
 * @param[out] key1B    Derived key1B
 * @return 0 if successful and a negative error code on failure
 */
static int post_cpace_kdf(const mbedtls_md_info_t *md,
    unsigned char key1[MBEDTLS_MD_MAX_SIZE],
    unsigned char key1A[MBEDTLS_CPACEOQUAKE_SID_LEN],
    unsigned char key1B[MBEDTLS_CPACEOQUAKE_SID_LEN]) {
    /* Note:
     * As the used CPace implementation creates two 32-Bit-Keys but the specification
     * of CpaceOQUAKE we follow (https://www.ietf.org/archive/id/draft-vos-cfrg-pqpake-01.html)
     * gives specific rules on how to expand the key, we choose to take the
     * client_key from CPace and expand two subkeys according to our specification.     *
     */
    // extract key1A and key1B
    unsigned char tagA[] = MBEDTLS_CPACEOQUAKE_DST "prskey";
    unsigned char tagB[] = MBEDTLS_CPACEOQUAKE_DST "outputkey";
    if (mbedtls_hkdf_expand(md, key1, md->size,
                              tagA, sizeof(MBEDTLS_CPACEOQUAKE_DST "prskey")-1,
                              key1A, MBEDTLS_CPACEOQUAKE_SID_LEN))
        return -1;
    if (mbedtls_hkdf_expand(md, key1, md->size,
                              tagB, sizeof(MBEDTLS_CPACEOQUAKE_DST "outputkey")-1,
                              key1B, MBEDTLS_CPACEOQUAKE_SID_LEN))
        return -1;
    return 0;
}

/**
 * @brief Derives PRS2 from PRS and key1A of CPace
 *
 * @param md            Message Digest Type to use for HKDF
 * @param prs           Original PRS used for derivation
 * @param prs_len       Length of prs
 * @param fullsid       fullsid of the connection
 * @param fullsid_len   Length of fullsid
 * @param msg1          CPace.Init Message
 * @param msg1_len      Length of msg1
 * @param msg2          CPace.Respond Message
 * @param msg2_len      Length of msg2
 * @param key1A         key1A derived from key1 from CPace
 * @param key1A_len     Length of key1A
 * @param[out] prs2     Output buffer for derived password related string 2
 *
 * @return 0 if successful and a negative error code on failure
 */
static int prs_to_prs2(const mbedtls_md_info_t *md,
                       const unsigned char *prs, const size_t prs_len,
                       const uint8_t *fullsid, const size_t fullsid_len,
                       const uint8_t *msg1, const size_t msg1_len,
                       const uint8_t *msg2, const size_t msg2_len,
                       const unsigned char key1A[MBEDTLS_CPACEOQUAKE_SID_LEN],
                       unsigned char prs2[MBEDTLS_CPACEOQUAKE_NKEY]) {
    int ret = -1;
    // derive second PRS from CPace Result
    // salt: DST || "CPaceOQUAKE" || fullsid || msg1 || msg2 || key1A
    const size_t salt_prs2_len = MBEDTLS_CPACEOQUAKE_DST_LEN + sizeof("CPaceOQUAKE")-1
        + fullsid_len + msg1_len + msg2_len + MBEDTLS_CPACEOQUAKE_SID_LEN;
    unsigned char *salt_prs2 = mbedtls_calloc(1, salt_prs2_len);
    if (!salt_prs2) goto cleanup;
    {
        unsigned char *temp_ptr = salt_prs2;
        memcpy(temp_ptr, MBEDTLS_CPACEOQUAKE_DST, MBEDTLS_CPACEOQUAKE_DST_LEN); temp_ptr += MBEDTLS_CPACEOQUAKE_DST_LEN;
        memcpy(temp_ptr, "CPaceOQUAKE", sizeof("CPaceOQUAKE")-1); temp_ptr += sizeof("CPaceOQUAKE")-1;
        memcpy(temp_ptr, fullsid, fullsid_len); temp_ptr += fullsid_len;
        memcpy(temp_ptr, msg1, msg1_len); temp_ptr += msg1_len;
        memcpy(temp_ptr, msg2, msg2_len); temp_ptr += msg2_len;
        memcpy(temp_ptr, key1A, MBEDTLS_CPACEOQUAKE_SID_LEN);
    }

    ret = mbedtls_hkdf(md, salt_prs2, salt_prs2_len, prs, prs_len,
        (const unsigned char *)MBEDTLS_CPACEOQUAKE_DST "PRS2", sizeof(MBEDTLS_CPACEOQUAKE_DST "PRS2")-1,
        prs2, MBEDTLS_CPACEOQUAKE_NKEY);

    cleanup:
    mbedtls_free(salt_prs2);
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
        /* This represents the CPaceOQUAKE.Init procedure */

        // first generate s1. We use it as part of the oquake fullsid
        // AND additionally as cpace-sid
        f_rng(p_rng, ctx->s1, MBEDTLS_CPACEOQUAKE_SID_LEN);
        memcpy(buf, &ctx->s1, MBEDTLS_CPACEOQUAKE_SID_LEN);
        *olen += MBEDTLS_CPACEOQUAKE_SID_LEN;

        // initialise cpace context and perform init step
        if ((ret = mbedtls_cpace_setup(&ctx->cpace,
            MBEDTLS_CPACE_INITIATOR,
            MBEDTLS_CPACE_P256_XMD_SHA_256_SSWU_NU_SHA256,
            (unsigned char *)MBEDTLS_CPACEOQUAKE_U_IDENTIFIER, sizeof(MBEDTLS_CPACEOQUAKE_U_IDENTIFIER)-1,
            (unsigned char *)MBEDTLS_CPACEOQUAKE_S_IDENTIFIER, sizeof(MBEDTLS_CPACEOQUAKE_S_IDENTIFIER)-1,
            ctx->s1, MBEDTLS_CPACEOQUAKE_SID_LEN,
            ctx->prs, ctx->prs_len)) != 0) goto cleanup;
        if ((ret = mbedtls_cpace_step_init(&ctx->cpace, f_rng, p_rng)) != 0) goto cleanup;

        // serialise CPace.Init msg (= Ya = ctx->cpace.Y), lv_encode it and concat it to buf
        unsigned char serialised_Ya[MBEDTLS_ECP_MAX_PT_LEN];
        size_t serialised_Ya_len;
        MBEDTLS_MPI_CHK(mbedtls_ecp_point_write_binary(&ctx->cpace.cs.h2c_cipher_suite.ecp_group, &ctx->cpace.Y,
            MBEDTLS_ECP_PF_UNCOMPRESSED, &serialised_Ya_len, serialised_Ya, sizeof(serialised_Ya)));
        *olen += serialised_Ya_len+2;
        if (*olen > len) {
            ret = MBEDTLS_ERR_CPACEOQUAKE_BUFFER_TOO_SMALL;
            goto cleanup;
        }
        lv_encode(serialised_Ya, serialised_Ya_len, buf + MBEDTLS_CPACEOQUAKE_SID_LEN);
        memcpy(ctx->msg1, serialised_Ya, serialised_Ya_len);
        ctx->msg1_len = serialised_Ya_len;
    } else if (ctx->role == MBEDTLS_ECJPAKE_SERVER) {
        /* This represents the CPaceOQUAKE.Respond procedure */

        // deserialise Ya from msg1
        mbedtls_ecp_point_read_binary(&ctx->cpace.cs.h2c_cipher_suite.ecp_group,
            &Ya, ctx->msg1, ctx->msg1_len);

        // perform CPace.Respond step
        unsigned char key1[MBEDTLS_MD_MAX_SIZE];
        if ((ret = mbedtls_cpace_step_respond(&ctx->cpace, &Ya, key1, f_rng, p_rng)) != 0)
            goto cleanup;

        // store msg2 from CPace Result
        mbedtls_ecp_point_write_binary(&ctx->cpace.cs.h2c_cipher_suite.ecp_group,
            &ctx->cpace.Y, MBEDTLS_ECP_PF_UNCOMPRESSED, &ctx->msg2_len,
            ctx->msg2, sizeof(ctx->msg2));

        // derive key1A and key1B
        unsigned char key1A[MBEDTLS_CPACEOQUAKE_SID_LEN];
        if ((ret = post_cpace_kdf(mbedtls_md_info_from_type(ctx->md_type), key1, key1A, ctx->key1B)) != 0)
            goto cleanup;

        // construct fullsid
        unsigned char s2[MBEDTLS_CPACEOQUAKE_SID_LEN];
        f_rng(p_rng, s2, MBEDTLS_CPACEOQUAKE_SID_LEN);
        unsigned char extended_sid[MBEDTLS_CPACEOQUAKE_SID_LEN];
        if ((ret = extend_sid_of_two(mbedtls_md_info_from_type(ctx->md_type),
            ctx->s1, s2, extended_sid)) != 0) goto cleanup;
        encode_sid(extended_sid, MBEDTLS_CPACEOQUAKE_SID_LEN,
            (unsigned char *)MBEDTLS_CPACEOQUAKE_U_IDENTIFIER, sizeof(MBEDTLS_CPACEOQUAKE_U_IDENTIFIER)-1,
            (unsigned char *)MBEDTLS_CPACEOQUAKE_S_IDENTIFIER, sizeof(MBEDTLS_CPACEOQUAKE_S_IDENTIFIER)-1,
            ctx->fullsid);
        ctx->fullsid_real_len = MBEDTLS_CPACEOQUAKE_SID_LEN + 12 +
            sizeof(MBEDTLS_CPACEOQUAKE_U_IDENTIFIER)-1 +
                sizeof(MBEDTLS_CPACEOQUAKE_S_IDENTIFIER)-1;

        // derive PRS2
        unsigned char prs2[MBEDTLS_CPACEOQUAKE_NKEY];
        if ((ret = prs_to_prs2(mbedtls_md_info_from_type(ctx->md_type),
            ctx->prs, ctx->prs_len, ctx->fullsid, ctx->fullsid_real_len,
            ctx->msg1, ctx->msg1_len, ctx->msg2, ctx->msg2_len,
            key1A, prs2)) != 0) goto cleanup;

        // set up OQUAKE context and perform OQUAKE.Init step
        if ((ret = mbedtls_oquake_setup(&ctx->oquake, ctx->md_type, prs2, sizeof(prs2),
            ctx->fullsid, ctx->fullsid_real_len)) != 0) goto cleanup;
        if ((ret = mbedtls_oquake_step_init(&ctx->oquake, ctx->msg3, f_rng, p_rng)) != 0)
            goto cleanup;

        // resp_msg = s2 || lv_encode(msg2) || lv_encode(msg3)
        {
            *olen = sizeof(s2) + 2 + ctx->msg2_len + 2 + sizeof(ctx->msg3);
            if (*olen > len) {
                ret = MBEDTLS_ERR_CPACEOQUAKE_BUFFER_TOO_SMALL;
                goto cleanup;
            }
            unsigned char *ptr = buf;
            memcpy(ptr, s2, sizeof(s2)); ptr += sizeof(s2);
            unsigned char lv_msg2[sizeof(ctx->msg2)+2];
            lv_encode(ctx->msg2, ctx->msg2_len, lv_msg2);
            memcpy(ptr, lv_msg2, ctx->msg2_len+2); ptr += ctx->msg2_len+2;
            unsigned char lv_msg3[sizeof(ctx->msg3)+2];
            lv_encode(ctx->msg3, sizeof(ctx->msg3), lv_msg3);
            memcpy(ptr, lv_msg3, sizeof(ctx->msg3)+2);
        }

    }

    cleanup:
    mbedtls_ecp_point_free(&Ya);
    return ret;
}


/**
 * @brief   Derives final secret from PRS and a full transcript
 *
 * @param md            Message Digest Type to use for HKDF
 * @param prs           Original PRS used for derivation
 * @param prs_len       Length of prs
 * @param fullsid       fullsid of the connection
 * @param fullsid_len   Length of fullsid
 * @param msg1          CPace.Init Message
 * @param msg1_len      Length of msg1
 * @param msg2          CPace.Respond Message
 * @param msg2_len      Length of msg2
 * @param msg3          OQUAKE.Init Message
 * @param msg3_len      Length of msg3
 * @param msg4          OQUAKE.Respond Message
 * @param msg4_len      Length of msg4
 * @param key1B         key1B derived from key1 from CPace
 * @param key2          key2 (resulting key from OQUAKE)
 * @param[OUT] secret   Final shared secret between Client and Server
 *
 * @return 0 if successful and a negative error code on failure
 */
static int cpaceoquake_kdf(const mbedtls_md_info_t *md,
                           uint8_t *prs, size_t prs_len,
                           uint8_t *fullsid, size_t fullsid_len,
                           uint8_t *msg1, size_t msg1_len, uint8_t *msg2, size_t msg2_len,
                           uint8_t *msg3, size_t msg3_len, uint8_t *msg4, size_t msg4_len,
                           unsigned char key1B[32],
                           unsigned char key2[MBEDTLS_CPACEOQUAKE_NKEY], unsigned char secret[MBEDTLS_CPACEOQUAKE_NKEY]) {

    int ret = -1;
    // salt: DST || "CPaceOQUAKE" || fullsid || msg1 || msg2 || msg3 || msg4 || key1B || key2
    const size_t salt_sk_len = MBEDTLS_CPACEOQUAKE_DST_LEN + sizeof("CPaceOQUAKE")-1
        + fullsid_len + msg1_len + msg2_len + msg3_len + msg4_len
        + 32 + MBEDTLS_CPACEOQUAKE_NKEY;
    unsigned char *salt_sk = mbedtls_calloc(1, salt_sk_len);
    if (!salt_sk) goto cleanup;

    {
        unsigned char *temp_ptr = salt_sk;
        memcpy(temp_ptr, MBEDTLS_CPACEOQUAKE_DST, MBEDTLS_CPACEOQUAKE_DST_LEN); temp_ptr += MBEDTLS_CPACEOQUAKE_DST_LEN;
        memcpy(temp_ptr, "CPaceOQUAKE", sizeof("CPaceOQUAKE")-1); temp_ptr += sizeof("CPaceOQUAKE")-1;
        memcpy(temp_ptr, fullsid, fullsid_len); temp_ptr += fullsid_len;
        memcpy(temp_ptr, msg1, msg1_len); temp_ptr += msg1_len;
        memcpy(temp_ptr, msg2, msg2_len); temp_ptr += msg2_len;
        memcpy(temp_ptr, msg3, msg3_len); temp_ptr += msg3_len;
        memcpy(temp_ptr, msg4, msg4_len); temp_ptr += msg4_len;
        memcpy(temp_ptr, key1B, 32); temp_ptr += 32;
        memcpy(temp_ptr, key2, MBEDTLS_CPACEOQUAKE_NKEY);
    }

    ret = mbedtls_hkdf(md, salt_sk, salt_sk_len, prs, prs_len,
        (const unsigned char *)MBEDTLS_CPACEOQUAKE_DST "sessionkey", sizeof(MBEDTLS_CPACEOQUAKE_DST "sessionkey")-1,
        secret, MBEDTLS_CPACEOQUAKE_NKEY);

    cleanup:
    mbedtls_free(salt_sk);
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

    if (ctx->role == MBEDTLS_ECJPAKE_CLIENT) {
        /* The server does not send a second message so nothing to do here */
        /* Client has already all knowledge to derive the final shared key */
    } else if (ctx->role == MBEDTLS_ECJPAKE_SERVER) {
        /* Begin of CPaceOQUAKE.ResponderFinish step */
        /* Read msg4 from buf, store it and derive key */
        if (len != sizeof(ctx->msg4)) {
            ret = MBEDTLS_ERR_CPACEOQUAKE_CORRUPT_MSG;
            goto cleanup;
        }

        memcpy(ctx->msg4, buf, len);

        if ((ret = mbedtls_oquake_step_finish(&ctx->oquake,
            ctx->msg4, sizeof(ctx->msg4), ctx->key2)) != 0)
            goto cleanup;
    }

    cleanup:

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

    if (ctx->role == MBEDTLS_ECJPAKE_CLIENT) {
        /* This represents the CPaceOQUAKE.InitiatorFinish procedure */

        // perform CPace.Finish step to get key1
        mbedtls_ecp_point_read_binary(&ctx->cpace.cs.h2c_cipher_suite.ecp_group,
            &Yb, ctx->msg2, ctx->msg2_len);
        unsigned char key1[MBEDTLS_MD_MAX_SIZE];
        if ((ret = mbedtls_cpace_step_finish(&ctx->cpace, &Yb, key1, f_rng, p_rng)) != 0)
            goto cleanup;

        // derive key1A and key1B
        unsigned char key1A[MBEDTLS_CPACEOQUAKE_SID_LEN];
        if ((ret = post_cpace_kdf(mbedtls_md_info_from_type(ctx->md_type), key1, key1A, ctx->key1B)) != 0)
            goto cleanup;

        // derive PRS2
        unsigned char prs2[MBEDTLS_CPACEOQUAKE_NKEY];
        if ((ret = prs_to_prs2(mbedtls_md_info_from_type(ctx->md_type),
            ctx->prs, ctx->prs_len, ctx->fullsid, ctx->fullsid_real_len,
            ctx->msg1, ctx->msg1_len, ctx->msg2, ctx->msg2_len,
            key1A, prs2)) != 0) goto cleanup;

        // set up oquake context and perform OQUAKE.Respond step
        if ((ret = mbedtls_oquake_setup(&ctx->oquake, ctx->md_type, prs2, sizeof(prs2),
            ctx->fullsid, ctx->fullsid_real_len)) != 0) goto cleanup;
        if ((ret = mbedtls_oquake_step_respond(&ctx->oquake, ctx->msg3, sizeof(ctx->msg3),
            ctx->msg4, ctx->key2)) != 0)
            goto cleanup;

        // fill message buffer and set olen
        if (len < sizeof(ctx->msg4)) {
            ret = MBEDTLS_ERR_CPACEOQUAKE_BUFFER_TOO_SMALL;
            goto cleanup;
        }
        memcpy(buf, ctx->msg4, sizeof(ctx->msg4));
        *olen = sizeof(ctx->msg4);

        /* derivation of client_key is performed in mbedtls_ecjpake_derive_secret() */

    } else if (ctx->role == MBEDTLS_ECJPAKE_SERVER) {
        /* Server does not have a second message to send */
        memset(buf, 0, len);
        *olen = 1;
    }

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

    if (len < MBEDTLS_CPACEOQUAKE_NKEY) {
        ret = MBEDTLS_ERR_CPACEOQUAKE_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    if ((ret = cpaceoquake_kdf(
        mbedtls_md_info_from_type(ctx->md_type),
        ctx->prs, ctx->prs_len,
        ctx->fullsid, ctx->fullsid_real_len,
        ctx->msg1, ctx->msg1_len,
        ctx->msg2, ctx->msg2_len,
        ctx->msg3, sizeof(ctx->msg3),
        ctx->msg4, sizeof(ctx->msg4),
        ctx->key1B, ctx->key2,
        buf)) != 0) goto cleanup;

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
        mbedtls_printf("  ECJPAKE test #0 (random handshake): ");
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
