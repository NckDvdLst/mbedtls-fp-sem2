//
// Created by Nick Leist on 13.06.26.
//
/*
 * References in the code are to https://www.ietf.org/archive/id/draft-vos-cfrg-pqpake-00.html#name-cpace-specification
 * and https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-13
 */

#include "common.h"
#if defined(MBEDTLS_ECJPAKE_C)

#include "mbedtls/cpace.h"

#include "md_wrap.h"
#include "mbedtls/rfc9380.h"
#include "mbedtls/platform.h"

#if !defined(MBEDTLS_ECJPAKE_ALT)

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * CONSTANT DEFINITIONS OF CIPHER SUITE PARAMS
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 */
/*
 * The values declared here are arrays specifying the parameters in the order of
 * mbedtls_cpace_cipher_suite_id. The values are used by mbedtls_cpace_load_cipher_suite
 * to build mbedtls_cpace_cipher_suite_t structures
 */

/*
 * md_type
 */
static const mbedtls_md_type_t mbedtls_cpace_cs_md_type[1] = {
    MBEDTLS_MD_SHA256
};

/*
 * DSI
 */
static const unsigned char mbedtls_cpace_cs_dsi_p256_sha256[] = "CPaceP256_XMD:SHA-256_SSWU_NU_";
static const unsigned char *mbedtls_cpace_cs_dsi[1] = {
    mbedtls_cpace_cs_dsi_p256_sha256
};
static const size_t mbedtls_cpace_cs_dsi_len[1] = {
    sizeof(mbedtls_cpace_cs_dsi_p256_sha256)-1
};

/*
 * DST
 */
static const unsigned char mbedtls_cpace_cs_dst_p256_sha256[] = "CPaceP256_XMD:SHA-256_SSWU_NU__DST";
static const unsigned char *mbedtls_cpace_cs_dst[1] = {
    mbedtls_cpace_cs_dst_p256_sha256
};
static const size_t mbedtls_cpace_cs_dst_len[1] = {
    sizeof(mbedtls_cpace_cs_dst_p256_sha256)-1
};

/*
 * H2C Cipher Suite
 */
static const mbedtls_h2c_cipher_suite_id mbedtls_cpace_cs_h2c_cs[1] = {
    MBEDTLS_H2C_P256_XMD_SHA_256_SSWU_NU_
};

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * STATIC FUNCTIONS
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 */

static void mbedtls_cpace_cipher_suite_free(mbedtls_cpace_cipher_suite_t *cipher_suite) {
    mbedtls_h2c_cipher_suite_free(&cipher_suite->h2c_cipher_suite);
}

static void mbedtls_cpace_cipher_suite_init(mbedtls_cpace_cipher_suite_t *cipher_suite) {
    mbedtls_h2c_cipher_suite_init(&cipher_suite->h2c_cipher_suite);
}

static int mbedtls_cpace_cipher_suite_load(mbedtls_cpace_cipher_suite_t *cipher_suite,
    mbedtls_cpace_cipher_suite_id id) {
    int ret = 0;

    cipher_suite->md_type = mbedtls_cpace_cs_md_type[id];
    cipher_suite->DSI = (unsigned char *)mbedtls_cpace_cs_dsi[id];
    cipher_suite->DSI_len = mbedtls_cpace_cs_dsi_len[id];
    cipher_suite->DST = (unsigned char *)mbedtls_cpace_cs_dst[id];
    cipher_suite->DST_len = mbedtls_cpace_cs_dst_len[id];
    if ((ret = mbedtls_h2c_load_cipher_suite(&cipher_suite->h2c_cipher_suite, mbedtls_cpace_cs_h2c_cs[id])) != 0)
        goto cleanup;

    return ret;

    cleanup:
    mbedtls_cpace_cipher_suite_free(cipher_suite);

    return ret;
}

/**
 *
 * @param data Input String to be prepended with its length
 * @param length Length of data
 * @param out Output buffer.
 *          Has to provide enough space for the encoding
 *          CAN be the same value as data (but buffer has to be longer than length then)
 * @return The size of the output string
 */
static size_t mbedtls_cpace_prepend_len(
    const unsigned char *data,
    size_t length,
    unsigned char *out
    ) {
    size_t length_original = length;
    unsigned char length_encoded[sizeof(size_t)];
    short length_encoded_len = 0;
    while (1) {
        if (length < 128) {
            length_encoded[length_encoded_len] = length;
            length_encoded_len++;
        } else {
            length_encoded[length_encoded_len] = length % 128 + 0x80;
            length_encoded_len++;
        }
        length >>= 7;
        if (length == 0) {
            break;
        }
    }
    // make sure data is not overwritten if data==out
    if (data == out) {
        memmove(out+length_encoded_len, data, length_original);
    } else {
        memcpy(out+length_encoded_len, data, length_original);
    }
    memcpy(out, length_encoded, length_encoded_len);
    return length_original + length_encoded_len;
}

/**
 * \brief Concatenates several strings and with their
 *        prepended length like in \c mbedtls_cpace_prepend_len()
 *
 * @param args          List of string pointers to the strings to concatenate
 * @param args_lenghts  List indicating the length for the corresponding \p args
 * @param args_count    Number of elements in \p args and \p args_lengths
 * @param out           Output buffer. Must be long enough.
 *                      Use \c mbedtls_cpace_leb128() to size it correctly.
 *                      MUST NOT be the same as any \p args.
 * @return Number of bytes written to \p out
 */
static size_t mbedtls_cpace_lv_cat(
    const unsigned char **args,
    const size_t *args_lenghts,
    const size_t args_count,
    unsigned char *out) {
    const unsigned char *in_ptr = args[0];
    unsigned char *out_ptr = out;
    for (size_t i = 0; i < args_count; i++) {
        size_t arg_len = args_lenghts[i];
        out_ptr += mbedtls_cpace_prepend_len(in_ptr, arg_len, out_ptr);
        in_ptr = args[i+1];
    }
    return out_ptr - out;
}

/**
 *
 * @param len Value which shall be converted to LEB128
 * @return Length in Bytes of the LEB128 representation of len
 *          or a negative error code
 */
static size_t mbedtls_cpace_leb128(size_t len) {
    size_t bytes = 0;

    do {
        bytes++;
        len >>= 7;
    } while (len > 0);

    return bytes;
}

/**
 * @brief Generator string function as specified for CPace
 *
 * @param DSI       Domain Separation Item
 * @param DSI_len   Length of \p DSI
 * @param PRS       Password Related String
 * @param PRS_len   Length of \p PRS
 * @param CI        Concatenated U and S identifier as from \c mbedtls_cpace_ctx
 *                  According to CPace specification they shall be concatenated
 *                  in a \c lv_cat() manner
 * @param CI_len    Length of \p CI
 * @param sid       Session Identifier
 * @param sid_len   Length of \p sid
 * @param s_in_bytes
 *                  Input block size of the used hash function
 *
 * @param out       Output buffer for the generator string
 * @return The number of bytes written to \p out
 */
static size_t mbedtls_cpace_generator_string(
    const unsigned char *DSI, const size_t DSI_len,
    const unsigned char *PRS, const size_t PRS_len,
    const unsigned char *CI, const size_t CI_len,
    const unsigned char *sid, const size_t sid_len,
    size_t s_in_bytes,
    unsigned char *out) {
    size_t ret = 0;
    size_t pl_PRS = mbedtls_cpace_leb128(PRS_len);
    size_t pl_DSI = mbedtls_cpace_leb128(DSI_len);
    long len_zpad = (long)(s_in_bytes - 1 - pl_PRS - PRS_len - pl_DSI - DSI_len);
    len_zpad = len_zpad < 0 ? 0 : len_zpad;

    const unsigned char *args1[2] = {
        DSI, PRS
    };
    size_t args1_lengths[2] = {
        DSI_len, PRS_len
    };
    ret += mbedtls_cpace_lv_cat(args1, args1_lengths, 2, out);

    memset(out+ret, 0, len_zpad);
    ret += mbedtls_cpace_prepend_len(out+ret, len_zpad, out+ret);

    const unsigned char *args2[2] = {
        CI, sid
    };
    size_t args2_lengths[2] = {
        CI_len, sid_len
    };
    ret += mbedtls_cpace_lv_cat(args2, args2_lengths, 2, out+ret);

    return ret;

}

/**
 * @brief   calculate_generator function as specified for CPace
 *          Encodes some information to get a point on a curve
 *
 * @param PRS           Password related string
 * @param PRS_len       Size of \p PRS
 * @param CI            Concatenated U and S identifier as from \c mbedtls_cpace_ctx
 *                      According to CPace specification they shall be concatenated
 *                      in a \c lv_cat() manner
 * @param CI_len        Length of \p CI
 * @param sid           Session Identifier
 * @param sid_len       Length of \p sid
 * @param cipher_suite  Cipher Suite Struct specifying properties of the used CPace Cipher Suite
 *                      Must be initialised and loaded
 * @param g             ECP Point Structure to fill in the derived generator
 *
 * @return \c 0 if successful
 * @return A negative error code on failure.
 */
static int mbedtls_cpace_calculate_generator(
    const unsigned char *PRS, size_t PRS_len,
    const unsigned char *CI, size_t CI_len,
    const unsigned char *sid, size_t sid_len,
    mbedtls_cpace_cipher_suite_t *cipher_suite,
    mbedtls_ecp_point *g) {
    int ret = 0;

    size_t gen_str_len = 0;
    const unsigned char s_in_bytes = mbedtls_md_info_from_type(cipher_suite->md_type)->block_size;
    gen_str_len += cipher_suite->DSI_len + PRS_len + CI_len + sid_len;
    gen_str_len += mbedtls_cpace_leb128(cipher_suite->DSI_len) +
                    mbedtls_cpace_leb128(PRS_len) +
                    mbedtls_cpace_leb128(CI_len) +
                    mbedtls_cpace_leb128(sid_len);
    // consider zpad.
    // len(prepend_len(PRS|DSI)) is assumed as len(PRS|DSI)+1 here, as with PRS or DSI being
    // larger than 127 byte that would automatically cause len(zpad) to be 0 regardless of
    // the prepended length being considered correctly
    gen_str_len += (s_in_bytes-1-PRS_len-1-cipher_suite->DSI_len) > 0 ?
                    (s_in_bytes-1-PRS_len-1-cipher_suite->DSI_len) : 0;
    unsigned char *gen_str = mbedtls_calloc(1, gen_str_len);
    if (!gen_str) {
        ret = MBEDTLS_ERR_CPACE_ALLOC_FAILED;
        goto cleanup;
    }

    mbedtls_cpace_generator_string(
        cipher_suite->DSI, cipher_suite->DSI_len,
        PRS, PRS_len,
        CI, CI_len,
        sid, sid_len, s_in_bytes,
        gen_str);

    // Z has to be set to 0 (point at infinity or zero) or 1 (standard)
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&g->Z, 1));

    ret = mbedtls_h2c_encode_to_curve(gen_str, gen_str_len,
        cipher_suite->DST, cipher_suite->DST_len, &cipher_suite->h2c_cipher_suite,
        &g->X, &g->Y);

    cleanup:
    mbedtls_free(gen_str);

    return ret;
}

/**
 * @brief Computes a sample scalar in a group
 *
 * @param y     MPI structure the scalar is put into
 * @param group_size_bits
 *              Size in bits of the order of the group (y shall not be bigger than that)
 * @param f_rng RNG function to use
 * @param p_rng Parameters for the \p f_rng
 *
 * @return \c 0 if successful
 * @return A negative error code on failure
 */
static int mbedtls_cpace_sample_scalar(
    mbedtls_mpi *y,
    size_t group_size_bits,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng) {
    int ret = 0;

    /*
     *It is RECOMMENDED to implement G.sample_scalar() as follows.
     * -  Set scalar = sample_random_bytes(G.group_size_bytes).
     * -  Then clear the most significant bits larger than G.group_size_bits.
     * -  Interpret the result as the little-endian encoding of an integer value
     *    and return the result
     */

    size_t group_size_bytes = group_size_bits / 8 + (group_size_bits%8 != 0);
    MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(y, group_size_bytes, f_rng, p_rng));
    size_t bitsize = group_size_bytes * 8;

    for (unsigned long i = bitsize-group_size_bits; i > 0; i--) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(y, bitsize-i, 0));
    }

    cleanup:

    return ret;
}

/**
 * @brief   Performs a safe scalar multiplication in a group by checking
 *          if the point is actually valid and if the result is not 0 or at infinity
 *
 * @param z     MPI structure where the X coordinate of the result of the
 *              multiplication is put into
 *              z = (s*X).X
 * @param s     Scalar value for the multiplication
 * @param X     Point to multiply
 * @param grp   The group environment for the multiplication
 * @param f_rng RNG function to use
 * @param p_rng Parameters for \p f_rng
 *
 * @return \0 if successful
 * @return A negative error code if some of the verification checks fails
 * @return A negative error code on generic failure
 */
static int mbedtls_cpace_scalar_mult_vfy(
    mbedtls_mpi *z,
    mbedtls_mpi *s,
    mbedtls_ecp_point *X,
    mbedtls_ecp_group *grp,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng
    ) {
    int ret = 0;

    mbedtls_ecp_point R;
    mbedtls_ecp_point_init(&R);

    MBEDTLS_MPI_CHK(mbedtls_ecp_check_pubkey(grp, X));

    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(grp, &R, s, X, f_rng, p_rng));

    if (mbedtls_ecp_is_zero(&R)) {
        ret = MBEDTLS_ERR_CPACE_POINT_IS_ZERO;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(z, &R.X));

    cleanup:
    mbedtls_ecp_point_free(&R);

    return ret;
}

/**
 * @brief   Computes a transcript of two Public Points
 *          in a scenario of clear initiator-responder assignment
 *
 * @param Ya    Public point of the initiator
 * @param Yb    Public point of the responder
 * @param grp   Group environment to enable point serialisation
 * @param transcript
 *              Output buffer for the transcript
 * @return \c 0 on success
 * @return A negative error code on failure
 */
static int mbedtls_cpace_transcript_ir(
    mbedtls_ecp_point *Ya,
    mbedtls_ecp_point *Yb,
    mbedtls_ecp_group *grp,
    unsigned char *transcript
    ) {
    int ret = 0;

    // first serialise Ya and Yb into a temporal buffer
    unsigned char *point_coordinates = NULL;
    point_coordinates = mbedtls_calloc(1, 2 * MBEDTLS_ECP_MAX_PT_LEN);
    if (!point_coordinates) {
        ret = MBEDTLS_ERR_CPACE_ALLOC_FAILED;
        goto cleanup;
    }
    size_t real_len_a;
    MBEDTLS_MPI_CHK(mbedtls_ecp_point_write_binary(grp, Ya, MBEDTLS_ECP_PF_UNCOMPRESSED,
        &real_len_a, point_coordinates, 2*MBEDTLS_ECP_MAX_PT_LEN));
    size_t real_len_b;
    MBEDTLS_MPI_CHK(mbedtls_ecp_point_write_binary(grp, Yb, MBEDTLS_ECP_PF_UNCOMPRESSED,
        &real_len_b, point_coordinates+real_len_a, 2*MBEDTLS_ECP_MAX_PT_LEN-real_len_a));
    size_t real_len = real_len_a + real_len_b;

    ret = (int)mbedtls_cpace_lv_cat((const unsigned char **)&point_coordinates, &real_len, 1, transcript);

    cleanup:
    mbedtls_free(point_coordinates);

    return ret;
}


/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * MAIN FUNCTIONS
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 */

void mbedtls_cpace_init(mbedtls_cpace_context *ctx) {
    mbedtls_cpace_cipher_suite_init(&ctx->cs);
    mbedtls_ecp_point_init(&ctx->Y);
    mbedtls_mpi_init(&ctx->y);
}

void mbedtls_cpace_free(mbedtls_cpace_context *ctx) {
    mbedtls_cpace_cipher_suite_free(&ctx->cs);
    mbedtls_ecp_point_free(&ctx->Y);
    mbedtls_mpi_free(&ctx->y);
    mbedtls_zeroize_and_free(ctx->U, ctx->U_len);
    mbedtls_zeroize_and_free(ctx->S, ctx->S_len);
    mbedtls_zeroize_and_free(ctx->sid, ctx->sid_len);
    mbedtls_zeroize_and_free(ctx->PRS, ctx->PRS_len);
}

int mbedtls_cpace_setup(mbedtls_cpace_context *ctx,
    mbedtls_cpace_role role,
    mbedtls_cpace_cipher_suite_id cipher_suite_id,
    unsigned char *U, size_t U_len,
    unsigned char *S, size_t S_len,
    unsigned char *sid, size_t sid_len,
    unsigned char *PRS, size_t PRS_len
    ) {
    int ret = 0;

    ctx->role = role;
    if ((ret = mbedtls_cpace_cipher_suite_load(&ctx->cs, cipher_suite_id)) != 0) goto cleanup;
    ctx->U = mbedtls_calloc(1, U_len);
    if (!ctx->U) {
        ret = MBEDTLS_ERR_CPACE_ALLOC_FAILED;
        goto cleanup;
    }
    memcpy(ctx->U, U, U_len);
    ctx->U_len = U_len;
    ctx->S = mbedtls_calloc(1, S_len);
    if (!ctx->S) {
        ret = MBEDTLS_ERR_CPACE_ALLOC_FAILED;
        goto cleanup;
    }
    memcpy(ctx->S, S, S_len);
    ctx->S_len = S_len;
    ctx->sid = mbedtls_calloc(1, sid_len);
    if (!ctx->sid) {
        ret = MBEDTLS_ERR_CPACE_ALLOC_FAILED;
        goto cleanup;
    }
    memcpy(ctx->sid, sid, sid_len);
    ctx->sid_len = sid_len;
    ctx->PRS = mbedtls_calloc(1, PRS_len);
    if (!ctx->PRS) {
        ret = MBEDTLS_ERR_CPACE_ALLOC_FAILED;
        goto cleanup;
    }
    memcpy(ctx->PRS, PRS, PRS_len);
    ctx->PRS_len = PRS_len;

    return ret;

    cleanup:
    mbedtls_cpace_free(ctx);

    return ret;
}

int mbedtls_cpace_step_init(
    mbedtls_cpace_context *ctx,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng
    ) {
    int ret = 0;

    // ECP Point initialisation for H2C generator g
    mbedtls_ecp_point g;
    mbedtls_ecp_point_init(&g);

    // build CI from U and S
    unsigned char *CI = mbedtls_calloc(1, ctx->U_len + ctx->S_len);
    if (!CI) {
        ret = MBEDTLS_ERR_CPACE_ALLOC_FAILED;
        goto cleanup;
    }
    memcpy(CI, ctx->U, ctx->U_len);
    memcpy(CI+ctx->U_len, ctx->S, ctx->S_len);

    /*
     * g = G.calculate_generator(H, PRS, U || S, sid)
     */
    MBEDTLS_MPI_CHK(mbedtls_cpace_calculate_generator(
        ctx->PRS, ctx->PRS_len,
        CI, ctx->U_len + ctx->S_len,
        ctx->sid, ctx->sid_len,
        &ctx->cs, &g));

    /*
     * ya = G.sample_scalar()
     */
    size_t group_size_bits = mbedtls_mpi_bitlen(&ctx->cs.h2c_cipher_suite.ecp_group.N);
    MBEDTLS_MPI_CHK(mbedtls_cpace_sample_scalar(&ctx->y, group_size_bits, f_rng, p_rng));

    /*
     * Ya = G.scalar_mult(ya, g)
     */
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx->cs.h2c_cipher_suite.ecp_group, &ctx->Y, &ctx->y, &g, f_rng, p_rng));

    cleanup:
    mbedtls_free(CI);
    mbedtls_ecp_point_free(&g);

    return ret;
}

int mbedtls_cpace_step_respond(
    mbedtls_cpace_context *ctx,
    mbedtls_ecp_point *Ya,
    unsigned char *ISK,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng
    ) {
    int ret = 0;

    // ECP Point initialisation for H2C generator g
    mbedtls_ecp_point g;
    mbedtls_ecp_point_init(&g);
    // MPI for ISK generation
    mbedtls_mpi K;
    mbedtls_mpi_init(&K);
    // buffers needed temporarily
    unsigned char *CI = NULL;
    unsigned char *h_input = NULL;
    unsigned char *h_input_pre = NULL;

    // build CI from U and S
    CI = mbedtls_calloc(1, ctx->U_len + ctx->S_len);
    if (!CI) {
        ret = MBEDTLS_ERR_CPACE_ALLOC_FAILED;
        goto cleanup;
    }
    memcpy(CI, ctx->U, ctx->U_len);
    memcpy(CI+ctx->U_len, ctx->S, ctx->S_len);

    /*
     * g = G.calculate_generator(H, PRS, U || S, sid)
     */
    MBEDTLS_MPI_CHK(mbedtls_cpace_calculate_generator(
        ctx->PRS, ctx->PRS_len,
        CI, ctx->U_len + ctx->S_len,
        ctx->sid, ctx->sid_len,
        &ctx->cs, &g));

    /*
     * yb = G.sample_scalar()
     */
    size_t group_size_bits = mbedtls_mpi_bitlen(&ctx->cs.h2c_cipher_suite.ecp_group.N);
    MBEDTLS_MPI_CHK(mbedtls_cpace_sample_scalar(&ctx->y, group_size_bits, f_rng, p_rng));

    /*
     * Yb = G.scalar_mult(yb, g)
     */
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx->cs.h2c_cipher_suite.ecp_group, &ctx->Y, &ctx->y, &g, f_rng, p_rng));

    /*
     * K = G.scalar_mult_vfy(yb, Ya)
     * If K = G.I, raise CPaceError
     */
    ret = mbedtls_cpace_scalar_mult_vfy(&K, &ctx->y, Ya, &ctx->cs.h2c_cipher_suite.ecp_group, f_rng, p_rng);
    if (ret != 0) goto cleanup;

    /*
     * ISK = H.hash(lv_cat(G.DSI || b"_ISK", sid, K) || transcript(Ya, Yb))
     */
    // construct hash input
    size_t max_h_input_len = ctx->cs.DSI_len+4 + mbedtls_cpace_leb128(ctx->cs.DSI_len+4) +
        ctx->sid_len + mbedtls_cpace_leb128(ctx->sid_len) +
            MBEDTLS_ECP_MAX_BYTES + mbedtls_cpace_leb128(MBEDTLS_ECP_MAX_BYTES) +
                MBEDTLS_ECP_MAX_PT_LEN*2 + mbedtls_cpace_leb128(MBEDTLS_ECP_MAX_PT_LEN*2);

    h_input = mbedtls_calloc(1, max_h_input_len);
    h_input_pre = mbedtls_calloc(1, max_h_input_len);
    if (!h_input || !h_input_pre) {
        ret = MBEDTLS_ERR_CPACE_ALLOC_FAILED;
        goto cleanup;
    }
    size_t h_input_len = 0;

    const unsigned char *lv_cat_args[3];
    size_t lv_cat_lens[3];
    {
        unsigned char *ptr = h_input_pre;

        lv_cat_args[0] = ptr;
        memcpy(ptr, ctx->cs.DSI, ctx->cs.DSI_len); ptr += ctx->cs.DSI_len;
        const unsigned char suffix[] = "_ISK";
        memcpy(ptr, &suffix, sizeof(suffix)-1); ptr += sizeof(suffix)-1;
        lv_cat_lens[0] = ptr - h_input_pre;

        lv_cat_args[1] = ptr;
        memcpy(ptr, ctx->sid, ctx->sid_len); ptr += ctx->sid_len;
        lv_cat_lens[1] = ptr - lv_cat_args[1];

        lv_cat_args[2] = ptr;
        size_t K_len = mbedtls_mpi_bitlen(&K)/8 + (mbedtls_mpi_bitlen(&K)%8 > 0);
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&K, ptr, K_len)); ptr += K_len;
        lv_cat_lens[2] = ptr - lv_cat_args[2];

        h_input_len += mbedtls_cpace_lv_cat(lv_cat_args, lv_cat_lens, 3, h_input);
        h_input_len += mbedtls_cpace_transcript_ir(Ya, &ctx->Y,
            &ctx->cs.h2c_cipher_suite.ecp_group, h_input+h_input_len);
    }

    mbedtls_md(mbedtls_md_info_from_type(ctx->cs.md_type), h_input, h_input_len, ISK);

    ret = 0;

    cleanup:
    mbedtls_free(CI);
    mbedtls_free(h_input);
    mbedtls_free(h_input_pre);
    mbedtls_ecp_point_free(&g);
    mbedtls_mpi_free(&K);

    return ret;
}

int mbedtls_cpace_step_finish(
    mbedtls_cpace_context *ctx,
    mbedtls_ecp_point *Yb,
    unsigned char *ISK,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng
    ) {
    int ret = 0;

    mbedtls_mpi K;
    mbedtls_mpi_init(&K);
    unsigned char *h_input = NULL;
    unsigned char *h_input_pre = NULL;

    /*
     * K = G.scalar_mult_vfy(ya, Yb)
     * If K = G.I, raise CPaceError
     */
    ret = mbedtls_cpace_scalar_mult_vfy(&K, &ctx->y, Yb, &ctx->cs.h2c_cipher_suite.ecp_group, f_rng, p_rng);
    if (ret != 0) goto cleanup;

    /*
     * ISK = H.hash(lv_cat(G.DSI || b"_ISK", sid, K) || transcript(Ya, Yb))
     */
    // construct hash input
    size_t max_h_input_len = ctx->cs.DSI_len+4 + mbedtls_cpace_leb128(ctx->cs.DSI_len+4) +
        ctx->sid_len + mbedtls_cpace_leb128(ctx->sid_len) +
            MBEDTLS_ECP_MAX_BYTES + mbedtls_cpace_leb128(MBEDTLS_ECP_MAX_BYTES) +
                MBEDTLS_ECP_MAX_PT_LEN*2 + mbedtls_cpace_leb128(MBEDTLS_ECP_MAX_PT_LEN*2);

    h_input = mbedtls_calloc(1, max_h_input_len);
    h_input_pre = mbedtls_calloc(1, max_h_input_len);
    if (!h_input || ! h_input_pre) {
        ret = MBEDTLS_ERR_CPACE_ALLOC_FAILED;
        goto cleanup;
    }
    size_t h_input_len = 0;

    const unsigned char *lv_cat_args[3];
    size_t lv_cat_lens[3];
    {
        unsigned char *ptr = h_input_pre;

        lv_cat_args[0] = ptr;
        memcpy(ptr, ctx->cs.DSI, ctx->cs.DSI_len); ptr += ctx->cs.DSI_len;
        const unsigned char suffix[] = "_ISK";
        memcpy(ptr, &suffix, sizeof(suffix)-1); ptr += sizeof(suffix)-1;
        lv_cat_lens[0] = ptr - lv_cat_args[0];

        lv_cat_args[1] = ptr;
        memcpy(ptr, ctx->sid, ctx->sid_len); ptr += ctx->sid_len;
        lv_cat_lens[1] = ptr - lv_cat_args[1];

        lv_cat_args[2] = ptr;
        size_t K_len = mbedtls_mpi_bitlen(&K)/8 + (mbedtls_mpi_bitlen(&K)%8 > 0);
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&K, ptr, K_len)); ptr += K_len;
        lv_cat_lens[2] = ptr - lv_cat_args[2];

        h_input_len += mbedtls_cpace_lv_cat(lv_cat_args, lv_cat_lens, 3, h_input);
        h_input_len += mbedtls_cpace_transcript_ir(&ctx->Y, Yb,
            &ctx->cs.h2c_cipher_suite.ecp_group, h_input+h_input_len);
    }

    mbedtls_md(mbedtls_md_info_from_type(ctx->cs.md_type), h_input, h_input_len, ISK);

    cleanup:
    mbedtls_mpi_free(&K);
    mbedtls_free(h_input);
    mbedtls_free(h_input_pre);

    return ret;
}

#endif

#if defined(MBEDTLS_SELF_TEST)

#include "mbedtls/error.h"

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * TESTING AREA
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 */

/*
 * Test vectors for prepend_len
 * taken from
 * https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-13#name-prepend_len-test-vectors
 */
static const unsigned char mbedtls_cpace_pl_test0_data[] = {};
static const unsigned char mbedtls_cpace_pl_test1_data[] = {
    0x31, 0x32, 0x33, 0x34
};
static const unsigned char mbedtls_cpace_pl_test2_data[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e
};
static const unsigned char mbedtls_cpace_pl_test3_data[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f
};

static const unsigned char mbedtls_cpace_pl_test0_out[] = {
    0x00
};
static const unsigned char mbedtls_cpace_pl_test1_out[] = {
    0x04, 0x31, 0x32, 0x33, 0x34
};
static const unsigned char mbedtls_cpace_pl_test2_out[] = {
    0x7f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e
};
static const unsigned char mbedtls_cpace_pl_test3_out[] = {
    0x80, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f
};

/*
 * Test vector for lv_cat. Taken from
 * https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-13#name-testvector-for-lv_cat
 */
static const unsigned char mbedtls_cpace_lc_test_arg0[] = {0x31, 0x32, 0x33, 0x34};
static const unsigned char mbedtls_cpace_lc_test_arg1[] = {0x35};
static const unsigned char mbedtls_cpace_lc_test_arg2[] = {};
static const unsigned char mbedtls_cpace_lc_test_arg3[] = {0x36, 0x37, 0x38};
static const unsigned char *mbedtls_cpace_lc_test_args[] = {
    mbedtls_cpace_lc_test_arg0, mbedtls_cpace_lc_test_arg1,
    mbedtls_cpace_lc_test_arg2, mbedtls_cpace_lc_test_arg3
};
static const size_t mbedtls_cpace_lc_test_args_lengths[] = {
    sizeof(mbedtls_cpace_lc_test_arg0), sizeof(mbedtls_cpace_lc_test_arg1),
    sizeof(mbedtls_cpace_lc_test_arg2), sizeof(mbedtls_cpace_lc_test_arg3)
};
static const size_t mbedtls_cpace_lc_test_args_count = sizeof(mbedtls_cpace_lc_test_args_lengths)/sizeof(size_t);
static const unsigned char mbedtls_cpace_lc_test_out[] = {
    0x04, 0x31, 0x32, 0x33, 0x34, 0x01, 0x35, 0x00, 0x03, 0x36, 0x37, 0x38
};

/*
 * Test Vectors for test for shared secret/ISK match
 */
static const unsigned char mbedtls_cpace_isk_test_prs[] = "Password";
static const unsigned char mbedtls_cpace_isk_test_s[] = "A_initiator";
static const unsigned char mbedtls_cpace_isk_test_u[] = "B_responder";
static const unsigned char mbedtls_cpace_isk_test_sid[] = {
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

int mbedtls_cpace_self_test(int verbose) {
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /*
     * Test prepend_len first
     */

    if (verbose != 0) {
        mbedtls_printf("  CPace test #0 (prepend_len): ");
    }

    unsigned char test0_out[sizeof(mbedtls_cpace_pl_test3_out)] = {0};
    unsigned char test0_zeros[sizeof(mbedtls_cpace_pl_test3_out)] = {0};

    // prepend_len test 0
    mbedtls_cpace_prepend_len(mbedtls_cpace_pl_test0_data,
                              sizeof(mbedtls_cpace_pl_test0_data), test0_out);
    if (memcmp(test0_out, mbedtls_cpace_pl_test0_out, sizeof(mbedtls_cpace_pl_test0_out)) != 0) {
        goto cleanup;
    }
    if (memcmp(&test0_out[sizeof(mbedtls_cpace_pl_test0_out)], test0_zeros,
        sizeof(test0_zeros) - sizeof(mbedtls_cpace_pl_test0_out)) != 0) {
        goto cleanup;
    }

    // prepend_len test 1
    mbedtls_cpace_prepend_len(mbedtls_cpace_pl_test1_data,
                              sizeof(mbedtls_cpace_pl_test1_data), test0_out);
    if (memcmp(test0_out, mbedtls_cpace_pl_test1_out, sizeof(mbedtls_cpace_pl_test1_out)) != 0) {
        goto cleanup;
    }
    if (memcmp(&test0_out[sizeof(mbedtls_cpace_pl_test1_out)], test0_zeros,
        sizeof(test0_zeros) - sizeof(mbedtls_cpace_pl_test1_out)) != 0) {
        goto cleanup;
    }

    // prepend_len test 2
    mbedtls_cpace_prepend_len(mbedtls_cpace_pl_test2_data,
                              sizeof(mbedtls_cpace_pl_test2_data), test0_out);
    if (memcmp(test0_out, mbedtls_cpace_pl_test2_out, sizeof(mbedtls_cpace_pl_test2_out)) != 0) {
        goto cleanup;
    }
    if (memcmp(&test0_out[sizeof(mbedtls_cpace_pl_test2_out)], test0_zeros,
        sizeof(test0_zeros) - sizeof(mbedtls_cpace_pl_test2_out)) != 0) {
        goto cleanup;
    }

    //prepend_len test 3
    mbedtls_cpace_prepend_len(mbedtls_cpace_pl_test3_data,
                              sizeof(mbedtls_cpace_pl_test3_data), test0_out);
    if (memcmp(test0_out, mbedtls_cpace_pl_test3_out, sizeof(mbedtls_cpace_pl_test3_out)) != 0) {
        goto cleanup;
    }

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

    /*
     * Test prepend_len first
     */

    if (verbose != 0) {
        mbedtls_printf("  CPace test #1 (lv_cat): ");
    }

    unsigned char test1_out[sizeof(mbedtls_cpace_lc_test_out)];
    mbedtls_cpace_lv_cat(
        mbedtls_cpace_lc_test_args,
        mbedtls_cpace_lc_test_args_lengths,
        mbedtls_cpace_lc_test_args_count,
        test1_out);
    if (memcmp(test1_out, mbedtls_cpace_lc_test_out, sizeof(mbedtls_cpace_lc_test_out)) != 0) {
        goto cleanup;
    }

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

    if (verbose != 0) {
        mbedtls_printf("  CPace test #2 (same key?): ");
    }

    mbedtls_cpace_context i_ctx;
    mbedtls_cpace_init(&i_ctx);
    mbedtls_cpace_setup(&i_ctx, MBEDTLS_CPACE_INITIATOR,
        MBEDTLS_CPACE_P256_XMD_SHA_256_SSWU_NU_SHA256,
        (unsigned char *)mbedtls_cpace_isk_test_u, sizeof(mbedtls_cpace_isk_test_u)-1,
        (unsigned char *)mbedtls_cpace_isk_test_s, sizeof(mbedtls_cpace_isk_test_s)-1,
        (unsigned char *)mbedtls_cpace_isk_test_sid, sizeof(mbedtls_cpace_isk_test_sid),
        (unsigned char *)mbedtls_cpace_isk_test_prs, sizeof(mbedtls_cpace_isk_test_prs)-1);

    mbedtls_cpace_context r_ctx;
    mbedtls_cpace_init(&r_ctx);
    mbedtls_cpace_setup(&r_ctx, MBEDTLS_CPACE_RESPONDER,
        MBEDTLS_CPACE_P256_XMD_SHA_256_SSWU_NU_SHA256,
        (unsigned char *)mbedtls_cpace_isk_test_u, sizeof(mbedtls_cpace_isk_test_u)-1,
        (unsigned char *)mbedtls_cpace_isk_test_s, sizeof(mbedtls_cpace_isk_test_s)-1,
        (unsigned char *)mbedtls_cpace_isk_test_sid, sizeof(mbedtls_cpace_isk_test_sid),
        (unsigned char *)mbedtls_cpace_isk_test_prs, sizeof(mbedtls_cpace_isk_test_prs)-1);

    mbedtls_cpace_step_init(&i_ctx, self_test_rng, NULL);
    unsigned char R_ISK[32];
    mbedtls_cpace_step_respond(&r_ctx, &i_ctx.Y, R_ISK, self_test_rng, NULL);
    unsigned char I_ISK[32];
    mbedtls_cpace_step_finish(&i_ctx, &r_ctx.Y, I_ISK, self_test_rng, NULL);

    if (memcmp(R_ISK, I_ISK, 32) != 0) {
        goto cleanup;
    }

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

    ret = 0;

    cleanup:
    mbedtls_cpace_free(&r_ctx);
    mbedtls_cpace_free(&i_ctx);

    return ret;

}


#endif

#endif
