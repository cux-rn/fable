/* Fable-AEAD (spec §3) and Fable-Hash (spec §5), C port of fable.py. Research draft. */
#ifndef FABLE_AEAD_H
#define FABLE_AEAD_H

#include <stddef.h>
#include <stdint.h>
#include "fable_p.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FABLE_KEY_BYTES 32
#define FABLE_NONCE_BYTES 24
#define FABLE_TAG_BYTES 32

/* out must have room for mlen + 32 bytes. Returns bytes written. */
FABLE_API size_t fable_aead_encrypt(uint8_t *out,
                                    const uint8_t key[32], const uint8_t nonce[24],
                                    const uint8_t *ad, size_t adlen,
                                    const uint8_t *m, size_t mlen);

/* Returns 0 on success (plaintext in out, clen-32 bytes), -1 on auth failure. */
FABLE_API int fable_aead_decrypt(uint8_t *out,
                                 const uint8_t key[32], const uint8_t nonce[24],
                                 const uint8_t *ad, size_t adlen,
                                 const uint8_t *c, size_t clen);

FABLE_API void fable_xof(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

#ifdef __cplusplus
}
#endif
#endif
