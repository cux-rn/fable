/* Fable-AEAD (spec §3) and Fable-Hash (spec §5), C port of fable.py. Research draft.
 * v0.3 parameter sets: FABLE_SET_DEFAULT = P_12 / P_8 (IV1 0x012020C8),
 *                      FABLE_SET_F       = P_12 / P_6 (IV1 0x012020C6, = v0.1 vectors). */
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

enum { FABLE_SET_DEFAULT = 0, FABLE_SET_F = 1 };

/* Per-set constants. */
FABLE_API int fable_set_light_rounds(int set);   /* 8 or 6 */
FABLE_API uint32_t fable_set_iv1(int set);       /* 0x012020C8 or 0x012020C6 */

/* out must have room for mlen + 32 bytes. Returns bytes written. */
FABLE_API size_t fable_aead_encrypt_set(uint8_t *out, int set,
                                        const uint8_t key[32], const uint8_t nonce[24],
                                        const uint8_t *ad, size_t adlen,
                                        const uint8_t *m, size_t mlen);
/* Returns 0 on success (plaintext in out, clen-32 bytes), -1 on auth failure. */
FABLE_API int fable_aead_decrypt_set(uint8_t *out, int set,
                                     const uint8_t key[32], const uint8_t nonce[24],
                                     const uint8_t *ad, size_t adlen,
                                     const uint8_t *c, size_t clen);

/* Default parameter set (P_8). */
FABLE_API size_t fable_aead_encrypt(uint8_t *out,
                                    const uint8_t key[32], const uint8_t nonce[24],
                                    const uint8_t *ad, size_t adlen,
                                    const uint8_t *m, size_t mlen);
FABLE_API int fable_aead_decrypt(uint8_t *out,
                                 const uint8_t key[32], const uint8_t nonce[24],
                                 const uint8_t *ad, size_t adlen,
                                 const uint8_t *c, size_t clen);

FABLE_API void fable_xof(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

#ifdef __cplusplus
}
#endif
#endif
