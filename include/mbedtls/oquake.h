/**
 * \file oquake.h
 *
 * \brief Post-Quantum secure PAKE "OQUAKE".
 */
/*
 *  Copyright Nick Leist
 */

#ifndef OQUAKE_H
#define OQUAKE_H

#include <stdint.h>

#include "mlkem_native.h"
#include "src/params.h"

#include "mbedtls/private_access.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/hkdf.h"

/*
 * OQUAKE is a PAKE built on a BUA-sKEM and KDF. If the BUA-sKEM provides security against
 * quantum-enabled attacks, then so does OQUAKE. It consists of three messages sent between 
 * initiator and responder, produced by the functions Init, Respond, and Finish, described 
 * below. Both parties take as input a password-related string PRS, an optional session 
 * identifier sid, and an optional client identifier U and server identifier S. Upon 
 * completion, both parties obtain matching session keys if their PRS, sid, key length 
 * (specified by N), and client and server identifiers match. Otherwise, they obtain random 
 * session keys.
 * https://www.ietf.org/archive/id/draft-vos-cfrg-pqpake-01.html#name-oquake-specification
 */

#define UC_PAKE_LABEL      "UC-PAKE-v1"
#define UC_PAKE_LABEL_LEN  10

#define AES_256_GCM_KEY_SIZE  32
#define AES_256_GCM_IV_SIZE   12
#define AES_256_GCM_TAG_SIZE  16


#define KEMELEON_B_BITS     2996
#define KEMELEON_T_BITS     128
#define KEMELEON_PER_POLY_BYTES  391   /* ceil((2996+128)/8) */
#define KEMELEON_EKBYTES   (MLKEM_K * KEMELEON_PER_POLY_BYTES + MLKEM_SYMBYTES)

#define OQUAKE_NSEC 32

#define OQUAKE_SHA256_LEN  32
#define OQUAKE_DST          "OQUAKE-v1"
#define OQUAKE_DST_LEN      (sizeof(OQUAKE_DST) - 1)   /* exclude NUL terminator    */

/* Fixed label used in the Expand info field */
#define LABEL_OQUAKE     "OQUAKE"
#define LABEL_OQUAKE_LEN (sizeof(LABEL_OQUAKE) - 1)

#define LABEL_TPAD       "T_pad"
#define LABEL_TPAD_LEN   (sizeof(LABEL_TPAD) - 1)
#define LABEL_SPAD       "S_pad"
#define LABEL_SPAD_LEN   (sizeof(LABEL_SPAD) - 1)
#define R_LEN 92

#define MBEDTLS_OQUAKE_NKC 64

#define MBEDTLS_ERR_OQUAKE_ALLOC_FAILED -0x1991

typedef enum { PQC_ENCRYPTION, PQC_DECRYPTION } PQC_CIPHER_MODE;

/**
 * OQUAKE context structure to be stored by the initiator
 */
typedef struct mbedtls_oquake_context {
    mbedtls_md_type_t MBEDTLS_PRIVATE(md_type);
    uint8_t *MBEDTLS_PRIVATE(prs);
    size_t MBEDTLS_PRIVATE(prs_len);
    uint8_t MBEDTLS_PRIVATE(sk)[2400];
    uint8_t MBEDTLS_PRIVATE(pk)[1184];
    uint8_t *MBEDTLS_PRIVATE(fullsid);
    size_t MBEDTLS_PRIVATE(fullsid_len);
} mbedtls_oquake_context;

/**
 * @brief Frees a given \c mbedtls_oquake_context and its child buffers
 *
 * @param ctx The context to free
 */
void mbedtls_oquake_free(mbedtls_oquake_context *ctx);

/**
 * Sets up an mbedtls_oquake_context with the provided values.
 * String values are copied into the struct and can be freed by calling \c mbedtls_oquake_free(ctx)
 *
 * @param ctx           The context to set up
 * @param md_type       The md type to use with oquake, e. g. #MBEDTLS_MD_SHA256
 * @param prs           The password related string
 * @param prs_len       Length of \p prs
 * @param fullsid       The SID to use for OQUAKE
 * @param fullsid_len   Length of \p fullsid
 *
 * @return \0 on success
 * @return \c MBEDTLS_ERR_OQUAKE_ALLOC_FAILED in case no memory could be allocated for string copies
 */
int mbedtls_oquake_setup(mbedtls_oquake_context *ctx,
                         mbedtls_md_type_t md_type,
                         unsigned char *prs, size_t prs_len,
                         unsigned char *fullsid, size_t fullsid_len
);

/**
 * \brief           Creates init message of OQUAKE flow 
 *
 * \param ctx   OQUAKE context of the initiator
 * \param[out] init_msg   Buffer to put OQUAKE init_msg into
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG parameter to be passed to \p f_rng. This
 *                  may be \c NULL if \p f_rng doesn't use a context.
 *
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int mbedtls_oquake_step_init(mbedtls_oquake_context *ctx, uint8_t *init_msg,
                    mbedtls_f_rng_t *f_rng, void *p_rng);


/**
 * \brief           Processes init message and creates response message of OQUAKE flow. 
 *                  Computes also the shared secret.
 *
 * \param ctx       OQUAKE context of the responder
 * \param init_msg  Message received from the initiator which was created by
 *                  \c mbedtls_oquake_step_init()
 * \param init_msg_len   L
 *                  Length of \p init_msg
 *
 * \param[out] resp_msg Buffer for the response message
 * \param[out] ss    The shared secret
 *
 * \return          \c 0 if successful.
 * \return          A negative error code on failure.
 */
int mbedtls_oquake_step_respond(mbedtls_oquake_context *ctx,
                    const unsigned char *init_msg, size_t init_msg_len,
                    uint8_t *resp_msg, unsigned char *ss);


/**
 * @brief Oquake.Finish Function
 *
 * @param ctx   The oquake context of the initiator
 * @param resp_msg
 *              The message created by \c mbedtls_oquake_step_respond()
 * @param resp_msg_len
 *              Length of \p resp_msg
 * @param ss[out]    The shared secret
 *
 * @return \c 0 on success
 */
int mbedtls_oquake_step_finish(
    const mbedtls_oquake_context *ctx,
    const unsigned char *resp_msg, size_t resp_msg_len,
    uint8_t *ss);

int mbedtls_oquake_self_test(int verbose);

#endif /* OQUAKE_H */