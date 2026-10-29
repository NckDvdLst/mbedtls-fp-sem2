//
// Created by Nick Leist on 10.06.26.
//

#ifndef MBED_TLS_RFC9380_H
#define MBED_TLS_RFC9380_H

#define MBEDTLS_ERR_H2C_BAD_INPUT -0x1984
#define MBEDTLS_ERR_H2C_UNKNOWN_ERROR -0x1985
#define MBEDTLS_ERR_H2C_ALLOC_FAILED -0x1986
#define MBEDTLS_ERR_H2C_CIPHER_SUITE_ERROR -0x1987
#define MBEDTLS_ERR_H2C_NO_SPACE -0x1988

#include "ecp.h"
#include "md.h"

typedef enum {
    MBEDTLS_H2C_P256_XMD_SHA_256_SSWU_NU_
} mbedtls_h2c_cipher_suite_id;

typedef enum {
    MBEDTLS_H2C_HASH_TO_CURVE,
    MBEDTLS_H2C_ENCODE_TO_CURVE
} mbedtls_h2c_encoding_type;

typedef enum {
    MBEDTLS_H2C_EXPAND_MESSAGE_XMD,
    MBEDTLS_H2C_EXPAND_MESSAGE_XOF
} mbedtls_h2c_expand_message;

typedef enum {
    MBEDTLS_H2C_MAPPING_SWU,
    MBEDTLS_H2C_MAPPING_SIMPLIFIED_SWU,
    MBEDTLS_H2C_MAPPING_SIMPLIFIED_SWU_AB0,
    MBEDTLS_H2C_MAPPING_ELLIGATOR2_MONTGOMERY
} mbedtls_h2c_mapping_function;

typedef struct mbedtls_h2c_cipher_suite_t {
    mbedtls_h2c_encoding_type encoding_type;
    mbedtls_ecp_group ecp_group; // for information about B and p
    mbedtls_mpi A; // A is not set to the authentic value in the ecp_group structure in some cases
                   // as documented in mbedtls_ecp_group description
    unsigned short m;
    unsigned short k;
    mbedtls_h2c_expand_message expand_message;
    mbedtls_md_type_t H;
    unsigned short L;
    mbedtls_h2c_mapping_function f;
    mbedtls_mpi Z;
    mbedtls_mpi h_eff;
} mbedtls_h2c_cipher_suite_t;

typedef struct mbedtls_h2c_field_elem {
    mbedtls_mpi **e;
    unsigned char m;
} mbedtls_h2c_field_elem;

typedef struct mbedlts_h2c_field_elem_list {
    mbedtls_h2c_field_elem **u;
    unsigned char count;
} mbedtls_h2c_field_elem_list;

void mbedtls_h2c_cipher_suite_init(
    mbedtls_h2c_cipher_suite_t *cipher_suite
    );

void mbedtls_h2c_cipher_suite_free(
    mbedtls_h2c_cipher_suite_t *cipher_suite
    );

int mbedtls_h2c_load_cipher_suite(
    mbedtls_h2c_cipher_suite_t *cipher_suite,
    mbedtls_h2c_cipher_suite_id id
    );

int mbedtls_h2c_encode_to_curve(
    unsigned char *msg, size_t msg_len,
    unsigned char *DST, size_t DST_len,
    mbedtls_h2c_cipher_suite_t *cipher_suite,
    mbedtls_mpi *x, mbedtls_mpi *y
    );

int mbedtls_h2c_self_test(int verbose);

#endif //MBED_TLS_RFC9380_H
