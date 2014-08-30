#ifndef __LIBCOUPLET_SCRAM_H__
#define __LIBCOUPLET_SCRAM_H__

#include <stdint.h>

#include "sha1.h"

void SCRAM_SHA1_ClientKey(const uint8_t *password, size_t len,
                          const uint8_t *salt, size_t salt_len, uint32_t i,
                          uint8_t key[SHA1_DIGEST_SIZE]);

void SCRAM_SHA1_ClientSignature(const uint8_t ClientKey[SHA1_DIGEST_SIZE],
                                const uint8_t *AuthMessage, size_t len,
                                uint8_t sign[SHA1_DIGEST_SIZE]);

void SCRAM_SHA1_ClientProof(const uint8_t ClientKey[SHA1_DIGEST_SIZE],
                            const uint8_t ClientSignature[SHA1_DIGEST_SIZE],
                            uint8_t proof[SHA1_DIGEST_SIZE]);

#endif /* __LIBCOUPLET_SCRAM_H__ */
