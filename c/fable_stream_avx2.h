/* Fable-Stream (spec §4) with 8 chunks encrypted in parallel on AVX2.
 * Output layout is identical to fable.py stream_encrypt():
 *   header(28) = "FBLS" || 0x01 || LE32(chunk) || nf(19)
 *   then for each chunk i (nchunks = len/chunk + 1, last chunk may be empty):  C_i || T_i(32)
 * Full middle chunks are processed 8 at a time with the states held in transposed
 * (word-major) AVX2 layout for the whole AEAD (init, AD, data, finalisation);
 * leftover chunks (< 8) and the final chunk use the scalar fable_aead_encrypt(). */
#ifndef FABLE_STREAM_AVX2_H
#define FABLE_STREAM_AVX2_H
#include <stddef.h>
#include <stdint.h>
#include "fable_p.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Returns bytes written = 28 + len + 32 * nchunks. `out` must have that much room. */
FABLE_API size_t fable_stream_encrypt_x8(uint8_t *out, const uint8_t key[32], const uint8_t nf[19],
                                         const uint8_t *data, size_t len, uint32_t chunk);
/* Same output, scalar path only (reference / comparison). */
FABLE_API size_t fable_stream_encrypt_scalar(uint8_t *out, const uint8_t key[32], const uint8_t nf[19],
                                             const uint8_t *data, size_t len, uint32_t chunk);
FABLE_API size_t fable_stream_output_size(size_t len, uint32_t chunk);
#ifdef __cplusplus
}
#endif
#endif
