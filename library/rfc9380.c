//
// Copyright Nick Leist 2026
//

// Implementation uses https://www.rfc-editor.org/info/rfc9380/ as reference

#include "common.h"

#if defined(MBEDTLS_ECJPAKE_C)
#include "mbedtls/rfc9380.h"

#if !defined(MBEDTLS_ECJPAKE_ALT)

#include "mbedtls/rfc9380.h"

#include <limits.h>
#include <string.h>

#include "md_wrap.h"
#include "mbedtls/bignum.h"
#include "mbedtls/md.h"
#include "mbedtls/platform.h"

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * CONSTANT DEFINITIONS OF CIPHER SUITE PARAMS
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 */
/*
 * The values declared here are arrays specifying the parameters in the order of
 * mbedtls_h2c_cipher_suite_id. The values are used by mbedtls_h2c_load_cipher_suite
 * to build mbedtls_h2c_cipher_suite_t structures
 */

/*
 * encoding_type
 */
static const mbedtls_h2c_encoding_type mbedtls_h2c_cs_encoding_type[1] = {
    MBEDTLS_H2C_ENCODE_TO_CURVE
};

/*
 * ecp_group (for parametric information of the field of the cipher suite)
 */
static const mbedtls_ecp_group_id mbedtls_h2c_cs_ecp_group_id[1] = {
    MBEDTLS_ECP_DP_SECP256R1
};

/*
 * A
 */
static const short mbedtls_h2c_cs_A[1] = {
    -3
};

/*
 * m
 */
static const unsigned short mbedtls_h2c_cs_m[1] = {
    1
};

/*
 * k
 */
static const unsigned short mbedtls_h2c_cs_k[1] = {
    128
};

/*
 * expand_message
 */
static const mbedtls_h2c_expand_message mbedtls_h2c_cs_expand_message[1] = {
    MBEDTLS_H2C_EXPAND_MESSAGE_XMD
};

/*
 * H (md_type)
 */
static const mbedtls_md_type_t mbedtls_h2c_cs_H[1] = {
    MBEDTLS_MD_SHA256
};

/*
 * L
 */
static const unsigned short mbedtls_h2c_cs_L[1] = {
    48
};

/*
 * f (mapping function)
 */
static const mbedtls_h2c_mapping_function mbedtls_h2c_cs_f[1] = {
    MBEDTLS_H2C_MAPPING_SIMPLIFIED_SWU
};

/*
 * Z
 */
static const short mbedtls_h2c_cs_Z[1] = {
    -10
};

/*
 * h_eff
 */
static const unsigned char mbedtls_h2c_p256_xmd_sha256_sswu__h_eff[1] = {0x01};
static const unsigned char (*mbedtls_h2c_cs_h_eff)[1] = {
    &mbedtls_h2c_p256_xmd_sha256_sswu__h_eff
};
static const unsigned char mbedtls_h2c_cs_h_eff_len[1] = {
    sizeof(mbedtls_h2c_p256_xmd_sha256_sswu__h_eff)
};


/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * STRUCT UTILITY FUNCTIONS
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 */

void mbedtls_h2c_cipher_suite_init(
    mbedtls_h2c_cipher_suite_t *cipher_suite
    ) {
    mbedtls_ecp_group_init(&cipher_suite->ecp_group);
    mbedtls_mpi_init(&cipher_suite->A);
    mbedtls_mpi_init(&cipher_suite->Z);
    mbedtls_mpi_init(&cipher_suite->h_eff);
}

void mbedtls_h2c_cipher_suite_free(
    mbedtls_h2c_cipher_suite_t *cipher_suite
    ) {
    mbedtls_ecp_group_free(&cipher_suite->ecp_group);
    mbedtls_mpi_free(&cipher_suite->A);
    mbedtls_mpi_free(&cipher_suite->Z);
    mbedtls_mpi_free(&cipher_suite->h_eff);
}

int mbedtls_h2c_load_cipher_suite(
    mbedtls_h2c_cipher_suite_t *cipher_suite,
    mbedtls_h2c_cipher_suite_id id
    ) {
    int ret = 0;

    cipher_suite->encoding_type = mbedtls_h2c_cs_encoding_type[id];
    if ((ret = mbedtls_ecp_group_load(&cipher_suite->ecp_group, mbedtls_h2c_cs_ecp_group_id[id])) != 0) {
        goto cleanup;
    }
    if ((ret = mbedtls_mpi_lset(&cipher_suite->A, mbedtls_h2c_cs_A[id])) != 0 ||
        (ret = mbedtls_mpi_mod_mpi(&cipher_suite->A, &cipher_suite->A, &cipher_suite->ecp_group.P)) != 0) {
        goto cleanup;
        }
    cipher_suite->m = mbedtls_h2c_cs_m[id];
    cipher_suite->k = mbedtls_h2c_cs_k[id];
    cipher_suite->expand_message = mbedtls_h2c_cs_expand_message[id];
    cipher_suite->H = mbedtls_h2c_cs_H[id];
    cipher_suite->L = mbedtls_h2c_cs_L[id];
    cipher_suite->f = mbedtls_h2c_cs_f[id];
    if ((ret = mbedtls_mpi_lset(&cipher_suite->Z, mbedtls_h2c_cs_Z[id])) != 0 ||
        (ret = mbedtls_mpi_mod_mpi(&cipher_suite->Z, &cipher_suite->Z, &cipher_suite->ecp_group.P)) != 0) {
        goto cleanup;
        }
    if ((ret = mbedtls_mpi_read_binary(&cipher_suite->h_eff,
        mbedtls_h2c_cs_h_eff[id], mbedtls_h2c_cs_h_eff_len[id])) != 0) {
        goto cleanup;
        }

    return ret;

    cleanup:
    mbedtls_h2c_cipher_suite_free(cipher_suite);

    return ret;

}

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * STATIC FUNCTIONS
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 */

static void mbedtls_h2c_field_elem_free(
    mbedtls_h2c_field_elem *u
    ) {
    for (int i = 0; i < u->m; i++) {
        mbedtls_mpi_free(u->e[i]);
    }
    mbedtls_free(u->e);
}

static void mbedtls_h2c_field_elem_init(
    mbedtls_h2c_field_elem *u
    ) {
    u->m = 0;
    u->e = NULL;
}

static int mbedtls_h2c_field_elem_setup(
    mbedtls_h2c_field_elem *u,
    unsigned char m
    ) {
    u->m = m;
    if (!u->e) {
        u->e = mbedtls_calloc(u->m, sizeof(mbedtls_mpi *));
        if (!u->e) return MBEDTLS_ERR_H2C_ALLOC_FAILED;
    } else {
        return MBEDTLS_ERR_H2C_ALLOC_FAILED;
    }
    for (int i = 0; i < u->m; i++) {
        u->e[i] = mbedtls_calloc(1, sizeof(mbedtls_mpi));
        if (!u->e[i]) return MBEDTLS_ERR_H2C_ALLOC_FAILED;
        mbedtls_mpi_init(u->e[i]);
    }
    return 0;
}

static mbedtls_mpi *mbedtls_h2c_field_elem_get(mbedtls_h2c_field_elem *u, int index) {
    return u->e[index];
}

static void mbedtls_h2c_field_elem_list_free(
    mbedtls_h2c_field_elem_list *elems
    ) {
    for (int i = 0; i < elems->count; i++) {
        mbedtls_h2c_field_elem_free(elems->u[i]);
    }
    mbedtls_free(elems->u);
}

static void mbedtls_h2c_field_elem_list_init(
    mbedtls_h2c_field_elem_list *elems
    ) {
    elems->count = 0;
    elems->u = NULL;
}

static int mbedtls_h2c_field_elem_list_setup(
    mbedtls_h2c_field_elem_list *elems,
    unsigned char count,
    unsigned char m
    ) {
    elems->count = count;
    if (!elems->u) {
        elems->u = mbedtls_calloc(count, sizeof(mbedtls_h2c_field_elem *));
        if (!elems->u) return MBEDTLS_ERR_H2C_ALLOC_FAILED;
    } else {
        return MBEDTLS_ERR_H2C_ALLOC_FAILED;
    }
    for (int i = 0; i < elems->count; i++) {
        elems->u[i] = mbedtls_calloc(1, sizeof(mbedtls_h2c_field_elem));
        if (!elems->u[i]) return MBEDTLS_ERR_H2C_ALLOC_FAILED;
        mbedtls_h2c_field_elem_init(elems->u[i]);
        if (mbedtls_h2c_field_elem_setup(elems->u[i], m) != 0) {
            return MBEDTLS_ERR_H2C_ALLOC_FAILED;
        }
    }
    return 0;
}

static mbedtls_h2c_field_elem *mbedtls_h2c_field_elem_list_get(
    mbedtls_h2c_field_elem_list *elems, int index
    ) {
    return elems->u[index];
}

// this refers to RFC 8017
static int mbedtls_h2c_I2OSP(
    mbedtls_mpi *x, int xLen,
    unsigned char *X) {
    int ret = MBEDTLS_ERR_H2C_BAD_INPUT;

    /*
     * declaration of necessary mbedtls_mpi structures
     *
     */
    // converted input value
    mbedtls_mpi m_xLen;
    mbedtls_mpi_init(&m_xLen);
    // temporary values
    mbedtls_mpi m_x_fits;
    mbedtls_mpi_init(&m_x_fits);
    mbedtls_mpi m_base;
    mbedtls_mpi_init(&m_base);
    mbedtls_mpi m_modular;
    mbedtls_mpi_init(&m_modular);

    // convert input to mbedtls_mpi structure
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&m_xLen, xLen));

    /*
     * 1. If x >= 256^xLen, output "integer too large" and stop.
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&m_base, 256));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&m_modular, UINT_MAX));
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&m_modular, &m_modular, 2));
    // m_x_fits = 256^m_xLen mod UINT_MAX+2
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&m_x_fits, &m_base, &m_xLen, &m_modular, NULL));
    // if m_xLen is too short to fit all positive integer values and is too short to fit m_x -> abort
    // first check necessary because of modulo in previous expression
    // because in case xLen>sizeof(int) the value of m_x_fits is only a residuent of the true result
    // then the second check won't work correctly and thus isn't performed
    if (mbedtls_mpi_cmp_int(&m_xLen, sizeof(int)) < 0 &&
        mbedtls_mpi_cmp_mpi(x, &m_x_fits) >= 0) {
        ret = MBEDTLS_ERR_H2C_BAD_INPUT;
        goto cleanup;
    }

    /*
     * 2. x = x_(xLen-1) * 256^(xLen-1) + x_(xLen-2) * 256^(xLen-2) + ... + x_1 * 256 + x_0
     *
     * 3. Let the octet X_i have the integer value x_(xLen-1) for 1 <= i <= xLen. Output the octet string
     * X = X_1 X_2 ... X_xLen.
     */
    mbedtls_mpi_write_binary(x, X, xLen);


    cleanup:
    mbedtls_mpi_free(&m_xLen);
    mbedtls_mpi_free(&m_x_fits);
    mbedtls_mpi_free(&m_base);
    mbedtls_mpi_free(&m_modular);

    return ret;
}

static int mbedtls_h2c_I2OSP_real_int(
    unsigned int x, int xLen,
    unsigned char *X
    ) {
    int ret = 0;
    mbedtls_mpi m_x;
    mbedtls_mpi_init(&m_x);
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&m_x, x));
    ret = mbedtls_h2c_I2OSP(&m_x, xLen, X);

    cleanup:
    mbedtls_mpi_free(&m_x);
    return ret;
}

static int mbedtls_h2c_OS2IP(
    const unsigned char *X,
    size_t xLen,
    mbedtls_mpi *x) {
    int ret = 0;
    if (xLen == 0) {
        ret = MBEDTLS_ERR_H2C_BAD_INPUT;
        goto cleanup;
    }
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(x, X, xLen));

    cleanup:

    return ret;
}

static void mbedtls_h2c_strxor(
    unsigned char *str1,
    unsigned char *str2,
    size_t str_len,
    unsigned char *out) {
    for (unsigned long i = 0; i < str_len; i++) {
        memset(out+i, str1[i]^str2[i], 1);
    }
}

static int mbedtls_h2c_expand_message_xmd(
    unsigned char *msg, size_t msg_len,
    unsigned char *DST, size_t DST_len,
    unsigned int len_in_bytes,
    unsigned char *uniform_bytes,
    mbedtls_md_type_t H
    ) {
    int ret = MBEDTLS_ERR_H2C_BAD_INPUT;

    /*
     * Parameters:
     *  - H, a hash function
     *  - b_in_bytes, b / 8 for b the output size of H in bits.
     *    For example, for b = 256, b_in_bytes = 32.
     *  - s_in_bytes, the input block size of H, measured in bytes.
     *    For example, for SHA-256, s_in_bytes = 64.
     */
    int b_in_bytes;
    int s_in_bytes;

    // dynamically allocated variables needed for the function
    unsigned char *DST_prime = NULL;
    unsigned char *Z_pad = NULL;
    unsigned char *msg_prime = NULL;
    unsigned char *b_0 = NULL;
    unsigned char *b_1 = NULL;
    unsigned char *b_i = NULL;
    unsigned char *uniform_bytes_tmp = NULL;
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);

    // read parametric info from hash type
    const mbedtls_md_info_t *md_info;
    if ((md_info = mbedtls_md_info_from_type(H)) != NULL) {
        b_in_bytes = md_info->size;
        s_in_bytes = md_info->block_size;
        ret = MBEDTLS_ERR_H2C_UNKNOWN_ERROR;
    } else goto cleanup;

    /*
     * 1. ell = ceil(len_in_bytes / b_in_bytes)
     */
    unsigned int ell = len_in_bytes / b_in_bytes;
    ell += len_in_bytes % b_in_bytes > 0 ? 1 : 0;

    /*
     * 2. ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255
     */
    if (ell > 255 ||
        len_in_bytes > 65535 ||
        DST_len > 255) {
        ret = MBEDTLS_ERR_H2C_BAD_INPUT;
        goto cleanup;
    }

    /*
     * 3. DST_prime = DST || I2OSP(len(DST), 1)
     */
    DST_prime = mbedtls_calloc(1, DST_len+1);
    if (!DST_prime) {
        ret = MBEDTLS_ERR_H2C_ALLOC_FAILED;
        goto cleanup;
    }
    memcpy(DST_prime, DST, DST_len);
    mbedtls_h2c_I2OSP_real_int((int)DST_len, 1, DST_prime+DST_len);

    /*
     * 4. Z_pad = I2OSP(0, s_in_bytes)
     */
    Z_pad = mbedtls_calloc(1, s_in_bytes);
    if (!Z_pad) {
        ret = MBEDTLS_ERR_H2C_ALLOC_FAILED;
        goto cleanup;
    }
    mbedtls_h2c_I2OSP_real_int(0, s_in_bytes, Z_pad);

    /*
     * 5. l_i_b_str = I2OSP(len_in_bytes, 2)
     */
    unsigned char l_i_b_str[2];
    mbedtls_h2c_I2OSP_real_int(len_in_bytes, 2, l_i_b_str);

    /*
     * 6. msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
     */
    size_t msg_prime_len = s_in_bytes+msg_len+2+1+(DST_len+1);
    msg_prime = mbedtls_calloc(1, msg_prime_len);
    if (!msg_prime) {
        ret = MBEDTLS_ERR_H2C_ALLOC_FAILED;
        goto cleanup;
    }
    {
        unsigned char *ptr = msg_prime;
        memcpy(ptr, Z_pad, s_in_bytes); ptr += s_in_bytes;
        memcpy(ptr, msg, msg_len); ptr += msg_len;
        memcpy(ptr, l_i_b_str, 2); ptr += 2;
        memset(ptr, 0, 1); ptr += 1;
        memcpy(ptr, DST_prime, (DST_len+1));
    }

    /*
     * 7.a MD context for the following operations
     */
    int md_res = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(H), 0);
    if (md_res != 0) {
        ret = md_res;
        goto cleanup;
    }

    /*
     * 7. b_0 = H(msg_prime)
     */
    b_0 = mbedtls_calloc(1, b_in_bytes);
    if (!b_0) {
        ret = MBEDTLS_ERR_H2C_ALLOC_FAILED;
        goto cleanup;
    }
    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, msg_prime, msg_prime_len);
    md_res = mbedtls_md_finish(&md_ctx, b_0);
    if (md_res != 0) {
        ret = md_res;
        goto cleanup;
    }

    /*
     * 8. b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
     */
    {
        b_1 = mbedtls_calloc(1, b_in_bytes);
        if (!b_1) {
            ret = MBEDTLS_ERR_H2C_ALLOC_FAILED;
            goto cleanup;
        }
        size_t h_inp_len = b_in_bytes + 1 + (DST_len+1);
        unsigned char *h_inp = mbedtls_calloc(1, h_inp_len);
        if (!h_inp) {
            goto cleanup;
        }
        unsigned char *ptr = h_inp;
        memcpy(ptr, b_0, b_in_bytes); ptr += b_in_bytes;
        memset(ptr, 1, 1); ptr += 1;
        memcpy(ptr, DST_prime, (DST_len+1));

        mbedtls_md_starts(&md_ctx);
        mbedtls_md_update(&md_ctx, h_inp, h_inp_len);
        md_res = mbedtls_md_finish(&md_ctx, b_1);
        if (md_res != 0) {
            ret = md_res;
            mbedtls_free(h_inp);
            goto cleanup;
        }

        mbedtls_free(h_inp);
    }

    /*
     *  9. for i in (2, ..., ell):
     * 10.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
     * 11. uniform_bytes = b_1 || .. || b_ell
     */
    b_i = mbedtls_calloc(1, b_in_bytes);
    {
        size_t h_inp_len = b_in_bytes + 1 + (DST_len+1);
        unsigned char *h_inp = mbedtls_calloc(1, h_inp_len);
        if (!h_inp) {
            ret = MBEDTLS_ERR_H2C_ALLOC_FAILED;
            goto cleanup;
        }

        uniform_bytes_tmp = mbedtls_calloc(1, ell * b_in_bytes);
        if (!uniform_bytes_tmp) {
            ret = MBEDTLS_ERR_H2C_ALLOC_FAILED;
            mbedtls_free(h_inp);
            goto cleanup;
        }

        // helper pointers to (hash-function) input and (final) output buffers
        unsigned char *i_ptr;
        unsigned char *o_ptr = uniform_bytes_tmp;

        memcpy(o_ptr, b_1, b_in_bytes); o_ptr += b_in_bytes;

        // before the loop, b_i is b_1
        memcpy(b_i, b_1, b_in_bytes);

        for (unsigned int i = 2; i <= ell; i++) {
            // build hash input
            i_ptr = h_inp;
            // b_i temporarily saves the strxor-result until being filled with the hash result
            // for the next iteration
            mbedtls_h2c_strxor(b_0, b_i, b_in_bytes, b_i);
            memcpy(i_ptr, b_i, b_in_bytes); i_ptr += b_in_bytes;
            *i_ptr = (unsigned char)i; i_ptr += 1;
            memcpy(i_ptr, DST_prime, (DST_len+1));

            // compute hash
            mbedtls_md_starts(&md_ctx);
            mbedtls_md_update(&md_ctx, h_inp, h_inp_len);
            md_res = mbedtls_md_finish(&md_ctx, b_i);
            if (md_res != 0) {
                ret = md_res;
                mbedtls_free(h_inp);
                goto cleanup;
            }

            // write result to the output buffer
            memcpy(o_ptr, b_i, b_in_bytes); o_ptr += b_in_bytes;
        }
        mbedtls_free(h_inp);
    }

    /*
     * 12. return substr(uniform_bytes, 0, len_in_bytes)
     */
    memcpy(uniform_bytes, uniform_bytes_tmp, len_in_bytes);
    ret = 0;


    cleanup:
    mbedtls_free(DST_prime);
    mbedtls_free(Z_pad);
    mbedtls_free(msg_prime);
    mbedtls_free(b_0);
    mbedtls_free(b_1);
    mbedtls_free(b_i);
    mbedtls_free(uniform_bytes_tmp);
    mbedtls_md_free(&md_ctx);

    return ret;
}

static int mbedtls_h2c_hash_to_field(
    unsigned char *msg, size_t msg_len,
    int count,
    mbedtls_h2c_field_elem_list *u_list,
    unsigned char *DST, size_t DST_len,
    mbedtls_h2c_cipher_suite_t *cipher_suite) {
    int ret = MBEDTLS_ERR_H2C_UNKNOWN_ERROR;

    /*
     * Parameters:
     * - DST, a domain separation tag (see Section 3.1).
     * - F, a finite field of characteristic p and order q = p^m.
     * - p, the characteristic of F (see immediately above).
     * - m, the extension degree of F, m >= 1 (see immediately above).
     * - L = ceil((ceil(log2(p)) + k) / 8), where k is the security
     *   parameter of the suite (e.g., k = 128).
     * - expand_message, a function that expands a byte string and
     *   domain separation tag into a uniformly random byte string
     *   (see Section 5.3).
     */

    /*
     * 1. len_in_bytes = count * m * L
     */
     unsigned int len_in_bytes = count * cipher_suite->m * cipher_suite->L;

    /*
     * 2. uniform_bytes = expand_message(msg, DST, len_in_bytes);
     */
    unsigned char *uniform_bytes = mbedtls_calloc(1, len_in_bytes);
    if (!uniform_bytes) {
        ret = MBEDTLS_ERR_H2C_ALLOC_FAILED;
        goto cleanup;
    }
    if (cipher_suite->expand_message == MBEDTLS_H2C_EXPAND_MESSAGE_XMD) {
        mbedtls_h2c_expand_message_xmd(msg, msg_len, DST, DST_len, len_in_bytes,
            uniform_bytes, cipher_suite->H);
    } else {
        /* NOT IMPLEMENTED */
        ret = MBEDTLS_ERR_H2C_CIPHER_SUITE_ERROR;
        goto cleanup;
    }

    /*
     * 3. for i in (0, ..., count - 1):
     */
    for (int i = 0; i < count; i++) {
    /*
     * 4.   for j in (0, ..., m - 1):
     */
        mbedtls_h2c_field_elem *u_i = mbedtls_h2c_field_elem_list_get(u_list, i);

        for (int j = 0; j < cipher_suite->m; j++) {
            /*
             * 5.      elm_offset = L * (j + i * m)
             */
            unsigned int elm_offset = cipher_suite->L * (j + i * cipher_suite->m);
            /*
             * 6. tv = substr(uniform_bytes, elm_offset, L)
             */
            unsigned char *tv = uniform_bytes + elm_offset;
            /*
             * 7. e_j = OS2IP(tv) mod p
             */
            mbedtls_mpi *e_j = mbedtls_h2c_field_elem_get(u_i, j);
            if ((ret = mbedtls_h2c_OS2IP(tv, cipher_suite->L, e_j)) != 0 ||
                (ret = mbedtls_mpi_mod_mpi(e_j, e_j, &cipher_suite->ecp_group.P)) != 0) {
                mbedtls_h2c_field_elem_free(u_i);
                goto cleanup;
            }
        }
        /*
         * 8. u_i = (e_0, ..., e_(m - 1))
         */
        // u_i is edited in place
    }

    /*
     * 9. return (u_0, ..., u_(count - 1))
     */
    ret = 0;

    cleanup:
    mbedtls_free(uniform_bytes);

    return ret;
}

/**
 * @param x an element of F
 * @param z an element of F such that (z^2) == x, if c is square in F (output)
 * @param cipher_suite
 * @return \c 0 if z is successfully set to the computed value
 *          or a negative error code in case of failures.
 */
static int mbedtls_h2c_sqrt_3mod4(
    mbedtls_mpi *x,
    mbedtls_mpi *z,
    mbedtls_h2c_cipher_suite_t *cipher_suite
    ) {
    int ret = MBEDTLS_ERR_H2C_UNKNOWN_ERROR;
    /*
     * Constants:
     * 1. c1 = (q + 1) / 4     # Integer arithmetic
     */
    mbedtls_mpi c1;
    mbedtls_mpi_init(&c1);
    // q = p^m = p because m = 1 for all fields this function is used for
    if (cipher_suite->m != 1) {
        ret = MBEDTLS_ERR_H2C_CIPHER_SUITE_ERROR;
        goto cleanup;
    }
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&c1, &cipher_suite->ecp_group.P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_div_int(&c1, NULL, &c1, 4));

    /*
     * Procedure:
     * 1. return x^c1
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(z, x, &c1, &cipher_suite->ecp_group.P, NULL));

    ret = 0;

    cleanup:
    mbedtls_mpi_free(&c1);

    return ret;
}

static int mbedtls_h2c_sqrt_ratio_3mod4(
    mbedtls_mpi *u,
    mbedtls_mpi *v,
    char *b,
    mbedtls_mpi *y,
    mbedtls_h2c_cipher_suite_t *cipher_suite
    ) {
    int ret = 0;

    // declaration of temporal variables
    mbedtls_mpi tv1;
    mbedtls_mpi_init(&tv1);
    mbedtls_mpi tv2;
    mbedtls_mpi_init(&tv2);
    mbedtls_mpi tv3;
    mbedtls_mpi_init(&tv3);
    mbedtls_mpi y1;
    mbedtls_mpi_init(&y1);
    mbedtls_mpi y2;
    mbedtls_mpi_init(&y2);

    /*
     * Constants:
     * 1. c1 = (q - 3) / 4     # Integer arithmetic
     * 2. c2 = sqrt(-Z)
     */
    mbedtls_mpi c1;
    mbedtls_mpi_init(&c1);
    mbedtls_mpi c2;
    mbedtls_mpi_init(&c2);

    // q = p^m = p because m = 1 for all fields this function is used for
    if (cipher_suite->m != 1) {
        ret = MBEDTLS_ERR_H2C_CIPHER_SUITE_ERROR;
        goto cleanup;
    }
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&c1, &cipher_suite->ecp_group.P, 3));
    MBEDTLS_MPI_CHK(mbedtls_mpi_div_int(&c1, NULL, &c1, 4));

    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&c2, &cipher_suite->ecp_group.P, &cipher_suite->Z));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&c2, &c2, &cipher_suite->ecp_group.P));
    if ((ret = mbedtls_h2c_sqrt_3mod4(&c2, &c2, cipher_suite)) < 0) {
        goto cleanup;
    } else {
        ret = MBEDTLS_ERR_H2C_UNKNOWN_ERROR;
    }

    /*
     * Procedure:
     * 1. tv1 = v^2
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tv1, v, v));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv1, &tv1, &cipher_suite->ecp_group.P));

    /*
     * 2. tv2 = u * v
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tv2, u, v));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv2, &tv2, &cipher_suite->ecp_group.P));

    /*
     * 3. tv1 = tv1 * tv2
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tv1, &tv1, &tv2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv1, &tv1, &cipher_suite->ecp_group.P));

    /*
     * 4. y1 = tv1^c1
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&y1, &tv1, &c1, &cipher_suite->ecp_group.P, NULL));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&y1, &y1, &cipher_suite->ecp_group.P));

    /*
     * 5. y1 = y1 * tv2
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&y1, &y1, &tv2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&y1, &y1, &cipher_suite->ecp_group.P));

    /*
     * 6. y2 = y1 * c2
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&y2, &y1, &c2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&y2, &y2, &cipher_suite->ecp_group.P));

    /*
     * 7. tv3 = y1^2
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tv3, &y1, &y1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv3, &tv3, &cipher_suite->ecp_group.P));

    /*
     * 8. tv3 = tv3 * v
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tv3, &tv3, v));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv3, &tv3, &cipher_suite->ecp_group.P));

    /*
     * 9. isQR = tv3 == u
     */
    // constant-time implementation as mbedtls_mpi_cmp_mpi may not be constant
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&tv3, &tv3, u));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv3, &tv3, &cipher_suite->ecp_group.P));
    const int isQR = (mbedtls_mpi_cmp_int(&tv3, 0) == 0);

    /*
     * 10. y = CMOV(y2, y1, isQR)
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_assign(y, &y1, isQR));
    MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_assign(y, &y2, !isQR));

    /*
     * 11. return (isQR, y)
     */
    *b = (char)isQR;
    ret = 0;

    cleanup:
    mbedtls_mpi_free(&c1);
    mbedtls_mpi_free(&c2);
    mbedtls_mpi_free(&tv1);
    mbedtls_mpi_free(&tv2);
    mbedtls_mpi_free(&tv3);
    mbedtls_mpi_free(&y1);
    mbedtls_mpi_free(&y2);

    return ret;
}

static int mbedtls_h2c_sgn0_m_eq_1(
    mbedtls_mpi *x
    ) {
    unsigned long sgn0;
    int ret;
    if ((ret = mbedtls_mpi_mod_int(&sgn0, x, 2)) < 0) return ret;
    return (int)sgn0;
}

static int mbedtls_h2c_map_to_curve_simple_swu(
    mbedtls_h2c_field_elem *u,
    mbedtls_h2c_cipher_suite_t *cipher_suite,
    mbedtls_mpi *x, mbedtls_mpi *y
    ) {
    int ret = 0;

    // declaration of temporal variables
    mbedtls_mpi tv1;
    mbedtls_mpi_init(&tv1);
    mbedtls_mpi tv2;
    mbedtls_mpi_init(&tv2);
    mbedtls_mpi tv3;
    mbedtls_mpi_init(&tv3);
    mbedtls_mpi tv4;
    mbedtls_mpi_init(&tv4);
    mbedtls_mpi tv5;
    mbedtls_mpi_init(&tv5);
    mbedtls_mpi tv6;
    mbedtls_mpi_init(&tv6);

    mbedtls_mpi y1;
    mbedtls_mpi_init(&y1);

    // get P from cipher_suite for shorter notation
    const mbedtls_mpi *P = &cipher_suite->ecp_group.P;

    // get arithmeticly usable field element from struct
    mbedtls_mpi *m_u = mbedtls_h2c_field_elem_get(u, 0);

    /*
     * 1. tv1 = u^2
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tv1, m_u, m_u));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv1, &tv1, P));

    /*
     * 2. tv1 = Z * tv1
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tv1, &cipher_suite->Z, &tv1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv1, &tv1, P));

    /*
     * 3. tv2 = tv1^2
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tv2, &tv1, &tv1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv2, &tv2, P));

    /*
     * 4. tv2 = tv2 + tv1
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&tv2, &tv2, &tv1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv2, &tv2, P));

    /*
     * 5. tv3 = tv2 + 1
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&tv3, &tv2, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv3, &tv3, P));

    /*
     * 6. tv3 = B * tv3
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tv3, &cipher_suite->ecp_group.B, &tv3));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv3, &tv3, P));

    /*
     * 7. tv4 = CMOV(Z, -tv2, tv2 != 0)
     */
    const int assign_negative_tv2 = (mbedtls_mpi_cmp_int(&tv2, 0) != 0);
    // tv2 = -tv2
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&tv2, P, &tv2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv2, &tv2, P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_assign(&tv4, &tv2, assign_negative_tv2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_assign(&tv4, &cipher_suite->Z, !assign_negative_tv2));
    // tv2 = -tv2 (= original tv2)
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&tv2, P, &tv2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv2, &tv2, P));

    /*
     * 8. tv4 = A * tv4
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tv4, &cipher_suite->A, &tv4));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv4, &tv4, P));

    /*
     * 9. tv2 = tv3^2
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tv2, &tv3, &tv3));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv2, &tv2, P));

    /*
     * 10. tv6 = tv4^2
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tv6, &tv4, &tv4));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv6, &tv6, P));

    /*
     * 11. tv5 = A * tv6
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tv5, &cipher_suite->A, &tv6));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv5, &tv5, P));

    /*
     * 12. tv2 = tv2 + tv5
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&tv2, &tv2, &tv5));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv2, &tv2, P));

    /*
     * 13. tv2 = tv2 * tv3
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tv2, &tv2, &tv3));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv2, &tv2, P));

    /*
     * 14. tv6 = tv6 * tv4
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tv6, &tv6, &tv4));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv6, &tv6, P));

    /*
     * 15. tv5 = B * tv6
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tv5, &cipher_suite->ecp_group.B, &tv6));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv5, &tv5, P));

    /*
     * 16. tv2 = tv2 + tv5
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&tv2, &tv2, &tv5));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv2, &tv2, P));

    /*
     * 17. x = tv1 * tv3
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(x, &tv1, &tv3));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(x, x, P));

    /*
     * 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
     */
    char is_gx1_square = 0;
    if ((ret = mbedtls_h2c_sqrt_ratio_3mod4(&tv2, &tv6, &is_gx1_square, &y1, cipher_suite)) != 0) {
        goto cleanup;
    }

    /*
     * 19. y = tv1 * u
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(y, &tv1, m_u));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(y, y, P));

    /*
     * 20. y = y * y1
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(y, y, &y1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(y, y, P));

    /*
     * 21. x = CMOV(x, tv3, is_gx1_square)
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_assign(x, &tv3, is_gx1_square));

    /*
     * 22. y = CMOV(y, y1, is_gx1_square)
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_assign(y, &y1, is_gx1_square));

    /*
     * 23. e1 = sgn0(u) == sgn0(y)
     */
    if (cipher_suite->m != 1) {
        // sgn0 is not yet implemented for extension fields (being fields with m>1)
        ret = MBEDTLS_ERR_H2C_CIPHER_SUITE_ERROR;
        goto cleanup;
    }
    int e1 = mbedtls_h2c_sgn0_m_eq_1(m_u);
    if (e1 < 0) goto cleanup;
    e1 = e1 == mbedtls_h2c_sgn0_m_eq_1(y);

    /*
     * 24. y = CMOV(-y, y, e1)
     */
    // use tv1 for -y as it is not needed anymore
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&tv1, P, y));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tv1, &tv1, P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_assign(y, &tv1, !e1));

    /*
     * 25. x = x / tv4
     */
    // tv4 = tv4^(-1)
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&tv4, &tv4, P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(x, x, &tv4));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(x, x, P));

    /*
     * 26. return (x, y)
     */
    ret = 0;

    cleanup:
    mbedtls_mpi_free(&tv1);
    mbedtls_mpi_free(&tv2);
    mbedtls_mpi_free(&tv3);
    mbedtls_mpi_free(&tv4);
    mbedtls_mpi_free(&tv5);
    mbedtls_mpi_free(&tv6);
    mbedtls_mpi_free(&y1);

    return ret;
}


/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * MAIN FUNCTIONS
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 */

int mbedtls_h2c_encode_to_curve(
    unsigned char *msg, size_t msg_len,
    unsigned char *DST, size_t DST_len,
    mbedtls_h2c_cipher_suite_t *cipher_suite,
    mbedtls_mpi *x, mbedtls_mpi *y
    ) {
    int ret = 0;

    /*
     * 1. u = hash_to_field(msg, 1)
     */
    mbedtls_h2c_field_elem_list u;
    mbedtls_h2c_field_elem_list_init(&u);
    mbedtls_h2c_field_elem_list_setup(&u, 1, cipher_suite->m);
    if ((ret = mbedtls_h2c_hash_to_field(msg, msg_len, 1, &u, DST, DST_len, cipher_suite)) != 0) {
        goto cleanup;
    }

    /*
     * 2. Q = map_to_curve(u[0])
     */
    if (cipher_suite->f != MBEDTLS_H2C_MAPPING_SIMPLIFIED_SWU) {
        // not implemented
        ret = MBEDTLS_ERR_H2C_CIPHER_SUITE_ERROR;
        goto cleanup;
    }
    if ((ret = mbedtls_h2c_map_to_curve_simple_swu(u.u[0], cipher_suite, x, y)) != 0) {
        goto cleanup;
    }

    /*
     * 3. P = clear_cofactor(Q)
     */
    if (mbedtls_mpi_cmp_int(&cipher_suite->h_eff, 1) != 0) {
        // clear_cofactor is not implemented as it is not needed for P256
        ret = MBEDTLS_ERR_H2C_CIPHER_SUITE_ERROR;
        goto cleanup;
    }

    /*
     * 4. return P
     */

    cleanup:
    mbedtls_h2c_field_elem_list_free(&u);

    return ret;
}

#endif

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * TESTING AREA
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 */

#if defined(MBEDTLS_SELF_TEST)

#include "mbedtls/error.h"

// for now these two are global test values as only this cipher suite is implemented
static const mbedtls_h2c_cipher_suite_id mbedtls_h2c_test_cipher_suite = MBEDTLS_H2C_P256_XMD_SHA_256_SSWU_NU_;
static const unsigned char mbedtls_h2c_test_DST[] = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_NU_";

// test individual values
static const unsigned char mbedtls_h2c_test0_msg[] = "";
static const unsigned char mbedtls_h2c_test1_msg[] = "abc";
static const unsigned char mbedtls_h2c_test2_msg[] = "abcdef0123456789";

static const unsigned char mbedtls_h2c_test0_x[] = {
    0xf8, 0x71, 0xca, 0xad, 0x25, 0xea, 0x3b, 0x59, 0xc1, 0x6c, 0xf8, 0x7c, 0x18, 0x94, 0x90,
    0x2f, 0x7e, 0x7b, 0x2c, 0x82, 0x2c, 0x3d, 0x3f, 0x73, 0x59, 0x6c, 0x5a, 0xce, 0x8d, 0xdd,
    0x14, 0xd1
};
static const unsigned char mbedtls_h2c_test1_x[] = {
    0xfc, 0x3f, 0x5d, 0x73, 0x4e, 0x8d, 0xce, 0x41, 0xdd, 0xac, 0x49, 0xf4, 0x7d, 0xd2, 0xb8,
    0xa5, 0x72, 0x57, 0x52, 0x2a, 0x86, 0x5c, 0x12, 0x4e, 0xd0, 0x2b, 0x92, 0xb5, 0x23, 0x7b,
    0xef, 0xa4
};
static const unsigned char mbedtls_h2c_test2_x[] = {
    0xf1, 0x64, 0xc6, 0x67, 0x4a, 0x02, 0x20, 0x7e, 0x41, 0x4c, 0x25, 0x7c, 0xe7, 0x59, 0xd3,
    0x5e, 0xdd, 0xc7, 0xf5, 0x5b, 0xe6, 0xd7, 0xf4, 0x15, 0xe2, 0xcc, 0x17, 0x7e, 0x5d, 0x8f,
    0xaa, 0x84
};

static const unsigned char mbedtls_h2c_test0_y[] = {
    0x87, 0xb9, 0xae, 0x23, 0x33, 0x5b, 0xee, 0x05, 0x7b, 0x99, 0xba, 0xc1, 0xe6, 0x85, 0x88,
    0xb1, 0x8b, 0x56, 0x91, 0xaf, 0x47, 0x62, 0x34, 0xb8, 0x97, 0x1b, 0xc4, 0xf0, 0x11, 0xdd,
    0xc9, 0x9b
};
static const unsigned char mbedtls_h2c_test1_y[] = {
    0xfe, 0x4d, 0x19, 0x7e, 0xcf, 0x5a, 0x62, 0x64, 0x5b, 0x96, 0x90, 0x59, 0x9e, 0x1d, 0x80,
    0xe8, 0x2c, 0x50, 0x0b, 0x22, 0xac, 0x70, 0x5a, 0x0b, 0x42, 0x1f, 0xac, 0x7b, 0x47, 0x15,
    0x78, 0x66
};
static const unsigned char mbedtls_h2c_test2_y[] = {
    0x3a, 0xa2, 0x74, 0x88, 0x1d, 0x30, 0xdb, 0x70, 0x48, 0x53, 0x68, 0xc0, 0x46, 0x7e, 0x97,
    0xda, 0x0e, 0x73, 0xc1, 0x8c, 0x1d, 0x00, 0xf3, 0x47, 0x75, 0xd0, 0x12, 0xb6, 0xfc, 0xee,
    0x7f, 0x97
};

int mbedtls_h2c_self_test(int verbose) {
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    mbedtls_mpi x;
    mbedtls_mpi_init(&x);
    mbedtls_mpi y;
    mbedtls_mpi_init(&y);

    mbedtls_mpi x_val;
    mbedtls_mpi_init(&x_val);
    mbedtls_mpi y_val;
    mbedtls_mpi_init(&y_val);

    mbedtls_h2c_cipher_suite_t cipher_suite;
    mbedtls_h2c_cipher_suite_init(&cipher_suite);
    mbedtls_h2c_load_cipher_suite(&cipher_suite, mbedtls_h2c_test_cipher_suite);

    if (verbose != 0) {
        // Test index (and values also) taken from
        // https://www.rfc-editor.org/info/rfc9380/#name-p256_xmdsha-256_sswu_nu_
        mbedtls_printf("  Hash2Curve test #0 (setup): ");
    }

    mbedtls_mpi_read_binary(&x_val, mbedtls_h2c_test0_x, sizeof(mbedtls_h2c_test0_x));
    mbedtls_mpi_read_binary(&y_val, mbedtls_h2c_test0_y, sizeof(mbedtls_h2c_test0_y));

    mbedtls_h2c_encode_to_curve((unsigned char *)mbedtls_h2c_test0_msg, sizeof(mbedtls_h2c_test0_msg)-1,
        (unsigned char *)mbedtls_h2c_test_DST, sizeof(mbedtls_h2c_test_DST)-1,
        &cipher_suite, &x, &y);

    if (mbedtls_mpi_cmp_mpi(&x, &x_val) != 0 || mbedtls_mpi_cmp_mpi(&y, &y_val) != 0) {
        goto cleanup;
    }

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

    if (verbose != 0) {
        // Test index (and values also) taken from
        // https://www.rfc-editor.org/info/rfc9380/#name-p256_xmdsha-256_sswu_nu_
        mbedtls_printf("  Hash2Curve test #1 (setup): ");
    }

    mbedtls_mpi_read_binary(&x_val, mbedtls_h2c_test1_x, sizeof(mbedtls_h2c_test1_x));
    mbedtls_mpi_read_binary(&y_val, mbedtls_h2c_test1_y, sizeof(mbedtls_h2c_test1_y));

    mbedtls_h2c_encode_to_curve((unsigned char *)mbedtls_h2c_test1_msg, sizeof(mbedtls_h2c_test1_msg)-1,
        (unsigned char *)mbedtls_h2c_test_DST, sizeof(mbedtls_h2c_test_DST)-1,
        &cipher_suite, &x, &y);

    if (mbedtls_mpi_cmp_mpi(&x, &x_val) != 0 || mbedtls_mpi_cmp_mpi(&y, &y_val) != 0) {
        goto cleanup;
    }

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

    if (verbose != 0) {
        // Test index (and values also) taken from
        // https://www.rfc-editor.org/info/rfc9380/#name-p256_xmdsha-256_sswu_nu_
        mbedtls_printf("  Hash2Curve test #2 (setup): ");
    }

    mbedtls_mpi_read_binary(&x_val, mbedtls_h2c_test2_x, sizeof(mbedtls_h2c_test2_x));
    mbedtls_mpi_read_binary(&y_val, mbedtls_h2c_test2_y, sizeof(mbedtls_h2c_test2_y));

    mbedtls_h2c_encode_to_curve((unsigned char *)mbedtls_h2c_test2_msg, sizeof(mbedtls_h2c_test2_msg)-1,
        (unsigned char *)mbedtls_h2c_test_DST, sizeof(mbedtls_h2c_test_DST)-1,
        &cipher_suite, &x, &y);

    if (mbedtls_mpi_cmp_mpi(&x, &x_val) != 0 || mbedtls_mpi_cmp_mpi(&y, &y_val) != 0) {
        goto cleanup;
    }

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

    ret = 0;

    cleanup:
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&y);
    mbedtls_mpi_free(&x_val);
    mbedtls_mpi_free(&y_val);
    mbedtls_h2c_cipher_suite_free(&cipher_suite);

    return ret;

}

#endif

#endif