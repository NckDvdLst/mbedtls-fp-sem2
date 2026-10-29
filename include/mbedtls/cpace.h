/**
 * \file cpace.h
 *
 * \brief Elliptic curve CPace
 */
/*
 *  Copyright Nick Leist
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_CPACE_H
#define MBEDTLS_CPACE_H
#include "mbedtls/private_access.h"

/*
 * CPace is a classical elliptic curve-based PAKE [CPACE].
 * This implementation uses
 * https://www.ietf.org/archive/id/draft-vos-cfrg-pqpake-00.html#name-cpace-specification
 * as reference.
 *
 * The flow of the protocol consists of three messages sent between initiator and responder,
 * produced by the functions Init, Respond, and Finish, described below.
 * Both parties take as input a password-related string PRS,
 * an optional unique shared session identifier sid,
 * and an optional client identifier U and server identifier S
 * (e.g., a device identifier, an IP address, or URL pertaining to the client and server).
 * Upon completion, both parties obtain matching session keys
 * if their PRS, sid, key length (specified by N), and client and server identifiers match.
 * Otherwise, they obtain random keys. In exceptional cases, the protocol aborts.
 *
 */
#include "rfc9380.h"
#include "mbedtls/build_info.h"

#include "mbedtls/ecp.h"
#include "mbedtls/md.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_ERR_CPACE_ALLOC_FAILED -0x1989
#define MBEDTLS_ERR_CPACE_POINT_IS_ZERO -0x1990

/*
 * CPACE cipher suite definitions
 */
typedef enum {
    MBEDTLS_CPACE_P256_XMD_SHA_256_SSWU_NU_SHA256
} mbedtls_cpace_cipher_suite_id;

typedef struct mbedtls_cpace_cipher_suite_t {
    mbedtls_md_type_t md_type;
    unsigned char *DSI;
    unsigned char DSI_len;
    unsigned char *DST;
    unsigned char DST_len;
    mbedtls_h2c_cipher_suite_t h2c_cipher_suite;
} mbedtls_cpace_cipher_suite_t;

/**
 * Roles in the EC CPace exchange
 */
typedef enum {
    MBEDTLS_CPACE_INITIATOR = 0,         /**< Client/Initiator               */
    MBEDTLS_CPACE_RESPONDER,             /**< Server/Responder               */
    MBEDTLS_CPACE_NONE,               /**< Undefined                      */
} mbedtls_cpace_role;

/**
 * EC CPace context structure.
 */
typedef struct mbedtls_cpace_context {
    mbedtls_cpace_role MBEDTLS_PRIVATE(role);
    mbedtls_cpace_cipher_suite_t MBEDTLS_PRIVATE(cs);
    mbedtls_ecp_point Y;
    mbedtls_mpi y;
    unsigned char *U;
    size_t U_len;
    unsigned char *S;
    size_t S_len;
    unsigned char *sid;
    size_t sid_len;
    unsigned char *PRS;
    size_t PRS_len;
} mbedtls_cpace_context;

/**
 * \brief           Initialize an CPace context.
 *
 * \param ctx       The CPace context to initialize.
 *                  This must not be \c NULL.
 */
void mbedtls_cpace_init(mbedtls_cpace_context *ctx);

/**
 * \brief           Set up an CPace context for use.
 *
 * \note            Currently the only values for hash/curve allowed with this
 *                  implementation are #MBEDTLS_MD_SHA256/#MBEDTLS_ECP_DP_SECP256R1.
 *
 * \param ctx       The CPace context to set up. This must be initialized.
 * \param role      The role of the caller. This must be either
 *                  #MBEDTLS_CPACE_INITIATOR or #MBEDTLS_CPACE_RESPONDER.
 * \param cipher_suite_id
 *                  The identifier of the cipher suite to use for the key exchange,
 *                  for example #MBEDTLS_CPACE_P256_XMD_SHA_256_SSWU_NU_SHA256
 * \param U         The identifier of the party acting as initiator
 * \param U_len     Length of \p U
 * \param S         The identifier of the party acting as server
 * \param S_len     Length of \p S
 * \param sid       Session identifier of the key exchange run
 * \param sid_len   Length of \p sid
 * \param PRS       The pre-shared secret (passphrase). This must be
 *                  a readable not empty buffer of length \p PRS_len Bytes. It need
 *                  only be valid for the duration of this call.
 * \param PRS_len   The length of the pre-shared secret \p PRS.
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int mbedtls_cpace_setup(mbedtls_cpace_context *ctx,
    mbedtls_cpace_role role,
    mbedtls_cpace_cipher_suite_id cipher_suite_id,
    unsigned char *U, size_t U_len,
    unsigned char *S, size_t S_len,
    unsigned char *sid, size_t sid_len,
    unsigned char *PRS, size_t PRS_len
);

/**
 * \brief           This clears a CPace context and frees any
 *                  embedded data structure.
 *
 * \param ctx       The CPace context to free. This may be \c NULL,
 *                  in which case this function does nothing. If it is not
 *                  \c NULL, it must point to an initialized CPace context.
 */
void mbedtls_cpace_free(mbedtls_cpace_context *ctx);

/**
 * @brief           CPace.Init function
 *
 * @param ctx       CPace Context of the initiator
 * @param f_rng     RNG function to use
 * @param p_rng     Parameters for \p f_rng
 *
 * @return \c 0 on success
 * @return A negative error code on failure
 */
int mbedtls_cpace_step_init(
    mbedtls_cpace_context *ctx,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng
);

/**
 * @brief           CPace.Respond function
 *
 * @param ctx       CPace Context of the responder
 * @param Ya        Public Point received from the initiator
 * @param ISK       Output buffer for the ISK (Shared Key)
 * @param f_rng     RNG function to use
 * @param p_rng     Parameters for \p f_rng
 *
 * @return \c 0 on success
 * @return A negative error code on failure
 */
int mbedtls_cpace_step_respond(
    mbedtls_cpace_context *ctx,
    mbedtls_ecp_point *Ya,
    unsigned char *ISK,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng
);

/**
 * @brief           CPace.Finish function
 *
 * @param ctx       CPace Context of the initiator
 * @param Yb        Public Point received from the responder
 * @param ISK       Output buffer for the ISK (Shared Key)
 * @param f_rng     RNG function to use
 * @param p_rng     Parameters for \p f_rng
 *
 * @return \c 0 on success
 * @return A negative error code on failure
 */
int mbedtls_cpace_step_finish(
    mbedtls_cpace_context *ctx,
    mbedtls_ecp_point *Yb,
    unsigned char *ISK,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng
);

#if defined(MBEDTLS_SELF_TEST)

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if a test failed
 */
int mbedtls_cpace_self_test(int verbose);

#endif /* MBEDTLS_SELF_TEST */

#ifdef __cplusplus
}
#endif


#endif /* cpace.h */
