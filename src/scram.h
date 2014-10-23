/* scram.h
 * strophe XMPP client library -- SCRAM-SHA1 helper functions
 *
 * Copyright (C) 2013 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

/** @file
 *  SCRAM-SHA1 helper functions.
 */

#ifndef __LIBSTROPHE_SCRAM_H__
#define __LIBSTROPHE_SCRAM_H__

/* make sure the stdint.h types are available */
#include "ostypes.h"

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

#endif /* __LIBSTROPHE_SCRAM_H__ */
