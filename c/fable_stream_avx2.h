/* Fable-Stream (spec §4) with 8 chunks processed in parallel on AVX2, v0.3 parameter sets.
 * Output layout is identical to fable.py stream_encrypt():
 *   header(28) = "FBLS" || 0x01 || LE32(chunk) || nf(19)
 *   then for each chunk i (nchunks = len/chunk + 1, last chunk may be empty):  C_i || T_i(32)
 * Full middle chunks are processed 8 at a time with the states held in transposed
 * (word-major) AVX2 layout for the whole AEAD; leftover chunks (< 8) and the final chunk use
 * the scalar fable_aead_*_set(). */
#ifndef FABLE_STREAM_AVX2_H
#define FABLE_STREAM_AVX2_H
#include <stddef.h>
#include <stdint.h>
#include "fable_p.h"
#include "fable_aead.h"
#ifdef __cplusplus
extern "C" {
#endif
FABLE_API size_t fable_stream_output_size(size_t len, uint32_t chunk);

/* Encrypt. Returns bytes written = 28 + len + 32 * nchunks. */
FABLE_API size_t fable_stream_encrypt_x8_set(uint8_t *out, int set, const uint8_t key[32], const uint8_t nf[19],
                                             const uint8_t *data, size_t len, uint32_t chunk);
FABLE_API size_t fable_stream_encrypt_scalar_set(uint8_t *out, int set, const uint8_t key[32], const uint8_t nf[19],
                                                 const uint8_t *data, size_t len, uint32_t chunk);
/* Decrypt a blob produced by the above. Returns plaintext length, or -1 on any failure
 * (bad header, truncation, tag mismatch; `out` is zeroed on failure). out needs bloblen bytes. */
FABLE_API long long fable_stream_decrypt_x8_set(uint8_t *out, int set, const uint8_t key[32],
                                                const uint8_t *blob, size_t bloblen);
FABLE_API long long fable_stream_decrypt_scalar_set(uint8_t *out, int set, const uint8_t key[32],
                                                    const uint8_t *blob, size_t bloblen);

/* Range helpers for multi-threaded callers: full (non-final) chunks [c0, c1); pointers refer to
 * chunk 0 of the whole file. Decrypt returns -1 if any tag in the range fails. */
FABLE_API size_t fable_stream_encrypt_range_x8(uint8_t *body, int set, const uint8_t key[32], const uint8_t nf[19],
                                               const uint8_t *data, uint32_t chunk, size_t c0, size_t c1);
FABLE_API long long fable_stream_decrypt_range_x8(uint8_t *out, int set, const uint8_t key[32], const uint8_t nf[19],
                                                  const uint8_t *body, uint32_t chunk, size_t c0, size_t c1);

/* Default parameter set wrappers. */
FABLE_API size_t fable_stream_encrypt_x8(uint8_t *out, const uint8_t key[32], const uint8_t nf[19],
                                         const uint8_t *data, size_t len, uint32_t chunk);
FABLE_API size_t fable_stream_encrypt_scalar(uint8_t *out, const uint8_t key[32], const uint8_t nf[19],
                                             const uint8_t *data, size_t len, uint32_t chunk);
#ifdef __cplusplus
}
#endif
#endif
