/* Fable-P permutation, C reference (v0.1 spec §2). Research draft, NOT for production. */
#ifndef FABLE_P_H
#define FABLE_P_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(FABLE_BUILD_DLL)
#define FABLE_API __declspec(dllexport)
#else
#define FABLE_API
#endif

#define FABLE_ROUNDS_HEAVY 12
#define FABLE_ROUNDS_LIGHT 6

/* Round constants RC[0..11] (spec §2.3): frac(ln p_i), first 32 bits. */
extern const uint32_t FABLE_RC[12];

/* Provisional rotation constants (spec §2.2). */
#define FABLE_R0 16
#define FABLE_R1 12
#define FABLE_R2 8
#define FABLE_R3 7

/* In-place Fable-P on 16 little-endian 32-bit words.
 * `rounds` in 1..12; round i uses RC[12 - rounds + i], i.e. light rounds use
 * the last RC entries, exactly as fable.py: permute(s, rounds). */
FABLE_API void fable_permute(uint32_t s[16], int rounds);

/* Same, with explicit rotation constants (for rotation screening). */
FABLE_API void fable_permute_rot(uint32_t s[16], int rounds,
                                 int r0, int r1, int r2, int r3);

/* Same as fable_permute_rot but with all round constants forced to zero
 * (used by the symmetry / slide checks). */
FABLE_API void fable_permute_noconst(uint32_t s[16], int rounds,
                                     int r0, int r1, int r2, int r3);

#ifdef __cplusplus
}
#endif
#endif /* FABLE_P_H */
