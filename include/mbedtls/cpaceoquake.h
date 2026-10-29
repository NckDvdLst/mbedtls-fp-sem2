/**
 * \file cpaceoquake.h
 *
 * \brief CPaceOQUAKE
 */
/*
 *  Copyright Nick Leist
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_CPACEOQUAKE_H
#define MBEDTLS_CPACEOQUAKE_H
#include "mbedtls/private_access.h"

/*
 * CPaceOQUAKE is a sequential composition of CPace and OQUAKE.
 * Whereas running CPace and OQUAKE in parallel realizes a worst-of-both worlds PAKE,
 * this sequential composition realizes a best-of-both worlds PAKE.
 * In other words, CPaceOQUAKE remains as secure as the strongest PAKE,
 * resisting attacks that break the classical CPace (e.g. by a quantum-capable attacker)
 * or attacks that break the quantum-resistant OQUAKE (e.g. by a flaw in the BUKEM).
 * This assumes that OQUAKE is instantiated with a quantum-resistant BUKEM.
 *
 * To be precise, CPaceOQUAKE first runs CPace using password-related string PRS,
 * establishing a session key SK1 with the associated transcript tr1.
 * It then initiates OQUAKE using the password-related string H(fullsid, PRS, tr1, SK1);
 * a secret derived from the the original password-related string
 * and the outputs from the CPace instance. Here, fullsid is the output of encode_sid(sid, U, S).
 * The final session key is then a hash of fullsid, the original password-related string,
 * both CPace and OQUAKE transcripts (tr1 and tr2, respectively),
 * and both session keys output from CPace and OQUAKE (SK1 and SK2, respectively),
 * i.e., H(fullsid, tr1, tr2, SK1, SK2).
 */
#include "mbedtls/build_info.h"

#include "mbedtls/ecp.h"
#include "mbedtls/md.h"

#include "mbedtls/crypto_cpace.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CPACEOQUAKE_DST "CPACEOQUAKE-v1.0.0"
#define CPACEOQUAKE_DST_LEN 18
#define CPACEOQUAKE_NKEY 32

/**
 * Roles in the EC J-PAKE exchange
 */
typedef enum {
    MBEDTLS_CPACEOQUAKE_CLIENT = 0,         /**< Client                         */
    MBEDTLS_CPACEOQUAKE_SERVER,             /**< Server                         */
    MBEDTLS_CPACEOQUAKE_NONE,               /**< Undefined                      */
} mbedtls_cpaceoquake_role;

#if !defined(MBEDTLS_ECJPAKE_ALT)
/**
 * CpaceOQUAKE context structure
 *
 * The Responder needs both parts (initiator and responder) while the initiator
 *
 */
typedef struct mbedtls_cpaceoquake_context {
    /** Context part symmetrically used by Initiator and Responder */
    mbedtls_md_type_t MBEDTLS_PRIVATE(md_type);          /**< Hash to use                    */
    mbedtls_cpaceoquake_role MBEDTLS_PRIVATE(role);      /**< Are we client or server?       */
    mbedtls_mpi MBEDTLS_PRIVATE(s);                      /**< Pre-shared secret (passphrase) */

    /** Context parts for Initiator */
    unsigned char MBEDTLS_PRIVATE(cpace_session_id)[16];
    unsigned char MBEDTLS_PRIVATE(cpace_p)[32];
    unsigned char MBEDTLS_PRIVATE(cpace_r)[32];
    uint8_t *MBEDTLS_PRIVATE(s1);

    /** Context parts for Responder */
    uint8_t *MBEDTLS_PRIVATE(fullsid);
    size_t MBEDTLS_PRIVATE(fullsid_len);
    uint8_t *MBEDTLS_PRIVATE(prs);
    size_t MBEDTLS_PRIVATE(prs_len);
    uint8_t *MBEDTLS_PRIVATE(msg1);
    size_t MBEDTLS_PRIVATE(msg1_len);
    uint8_t *MBEDTLS_PRIVATE(msg2);
    size_t MBEDTLS_PRIVATE(msg2_len);
    uint8_t *MBEDTLS_PRIVATE(msg3);
    size_t MBEDTLS_PRIVATE(msg3_len);
    uint8_t *MBEDTLS_PRIVATE(key1B);
} mbedtls_cpaceoquake_context;

#else  /* MBEDTLS_ECJPAKE_ALT */
typedef struct mbedtls_cpaceoquake_context {
    int dummy;
} mbedtls_cpaceoquake_context;
#endif /* MBEDTLS_ECJPAKE_ALT */

/**
 * \brief           Encodes a byte string with a two-byte, big-endian length prefix.
 *
 * \param msg       Message to be encoded
 * \param msg_len   Length of msg in bytes
 * \param out       Output buffer for encoded msg
 *
 * \return          Pointer to the encoded message
 *
 */
int lv_encode(const uint8_t *msg, size_t msg_len, uint8_t **out);

/**
 * \brief           Decodes a byte string assumed to have a two-byte, big-endian length prefix.
 *
 * \param msg       Message to be decoded (is performed in-place)
 *
 * \return          Length of the decoded message
 *
 */
size_t lv_decode(uint8_t *msg);

/**
 * \brief           Initialize an CPaceOQUAKE context.
 *
 * \param ctx       The CPaceOQUAKE context to initialize.
 *                  This must not be \c NULL.
 */
void mbedtls_cpaceoquake_init(mbedtls_cpaceoquake_context *ctx);

/**
 * \brief           Set up an CPaceOQUAKE context for use.
 *
 * \note            Currently the only values for hash/curve allowed by the
 *                  standard are #MBEDTLS_MD_SHA256/#MBEDTLS_ECP_DP_SECP256R1.
 *
 * \note            The \c curve param is unused and only in the parameter set
 *                  for broader compatibility with the ECJPAKE interface
 *
 * \param ctx       The CPaceOQUAKE context to set up. This must be initialized.
 * \param role      The role of the caller. This must be either
 *                  #MBEDTLS_ECJPAKE_CLIENT or #MBEDTLS_ECJPAKE_SERVER.
 * \param hash      The identifier of the hash function to use,
 *                  for example #MBEDTLS_MD_SHA256.
 * \param curve     The identifier of the elliptic curve to use,
 *                  for example #MBEDTLS_ECP_DP_SECP256R1.
 *                  Can also be \c NULL since it is unused and only preserved for
 *                  compatibility reasons
 * \param secret    The pre-shared secret (passphrase). This must be
 *                  a readable not empty buffer of length \p len Bytes. It need
 *                  only be valid for the duration of this call.
 * \param len       The length of the pre-shared secret \p secret.
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int mbedtls_cpaceoquake_setup(mbedtls_cpaceoquake_context *ctx,
                          mbedtls_cpaceoquake_role role,
                          mbedtls_md_type_t hash,
                          mbedtls_ecp_group_id curve,
                          const unsigned char *secret,
                          size_t len);

/**
 * \brief           Check if an CPaceOQUAKE context is ready for use.
 *
 * \param ctx       The CPaceOQUAKE context to check. This must be
 *                  initialized.
 *
 * \return          \c 0 if the context is ready for use.
 * \return          #MBEDTLS_ERR_ECP_BAD_INPUT_DATA otherwise.
 */
int mbedtls_cpaceoquake_check(const mbedtls_cpaceoquake_context *ctx);

/**
 * \brief           Generate and write the first round message
 *
 * \param ctx       The CPaceOQUAKE context to use. This must be
 *                  initialized and set up.
 * \param buf       The buffer to write the contents to. This must be a
 *                  writable buffer of length \p len Bytes.
 * \param len       The length of \p buf in Bytes.
 * \param olen      The address at which to store the total number
 *                  of Bytes written to \p buf. This must not be \c NULL.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG parameter to be passed to \p f_rng. This
 *                  may be \c NULL if \p f_rng doesn't use a context.
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int mbedtls_cpaceoquake_write_round_one(mbedtls_cpaceoquake_context *ctx,
                                    unsigned char *buf, size_t len, size_t *olen,
                                    mbedtls_f_rng_t *f_rng,
                                    void *p_rng);

/**
 * \brief           Read and process the first round message
 *
 * \param ctx       The CPaceOQUAKE context to use. This must be initialized
 *                  and set up.
 * \param buf       The buffer holding the first round message. This must
 *                  be a readable buffer of length \p len Bytes.
 * \param len       The length in Bytes of \p buf.
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int mbedtls_cpaceoquake_read_round_one(mbedtls_cpaceoquake_context *ctx,
                                   const unsigned char *buf,
                                   size_t len);

/**
 * \brief           Generate and write the second round message
 *
 * \param ctx       The CPaceOQUAKE context to use. This must be initialized,
 *                  set up, and already have performed round one.
 * \param buf       The buffer to write the round two contents to.
 *                  This must be a writable buffer of length \p len Bytes.
 * \param len       The size of \p buf in Bytes.
 * \param olen      The address at which to store the total number of Bytes
 *                  written to \p buf. This must not be \c NULL.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG parameter to be passed to \p f_rng. This
 *                  may be \c NULL if \p f_rng doesn't use a context.
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int mbedtls_cpaceoquake_write_round_two(mbedtls_cpaceoquake_context *ctx,
                                    unsigned char *buf, size_t len, size_t *olen,
                                    mbedtls_f_rng_t *f_rng,
                                    void *p_rng);

/**
 * \brief           Read and process the second round message
 *
 * \param ctx       The CPaceOQUAKE context to use. This must be initialized
 *                  and set up and already have performed round one.
 * \param buf       The buffer holding the second round message. This must
 *                  be a readable buffer of length \p len Bytes.
 * \param len       The length in Bytes of \p buf.
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int mbedtls_cpaceoquake_read_round_two(mbedtls_cpaceoquake_context *ctx,
                                   const unsigned char *buf,
                                   size_t len);

/**
 * \brief           Derive the shared secret
 *
 * \param ctx       The CPaceOQUAKE context to use. This must be initialized,
 *                  set up and have performed both round one and two.
 * \param buf       The buffer to write the derived secret to. This must
 *                  be a writable buffer of length \p len Bytes.
 * \param len       The length of \p buf in Bytes.
 * \param olen      The address at which to store the total number of Bytes
 *                  written to \p buf. This must not be \c NULL.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG parameter to be passed to \p f_rng. This
 *                  may be \c NULL if \p f_rng doesn't use a context.
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int mbedtls_cpaceoquake_derive_secret(mbedtls_cpaceoquake_context *ctx,
                                  unsigned char *buf, size_t len, size_t *olen,
                                  mbedtls_f_rng_t *f_rng,
                                  void *p_rng);

/**
 * \brief           This clears an CPaceOQUAKE context and frees any
 *                  embedded data structure.
 *
 * \param ctx       The CPaceOQUAKE context to free. This may be \c NULL,
 *                  in which case this function does nothing. If it is not
 *                  \c NULL, it must point to an initialized CPaceOQUAKE context.
 */
void mbedtls_cpaceoquake_free(mbedtls_cpaceoquake_context *ctx);

#if defined(MBEDTLS_SELF_TEST)

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if a test failed
 */
int mbedtls_cpaceoquake_self_test(int verbose);

#endif /* MBEDTLS_SELF_TEST */

#ifdef __cplusplus
}
#endif


#endif /* cpaceoquake.h */
