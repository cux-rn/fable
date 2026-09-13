#!/usr/bin/env bash
# Build Fable C library (DLL for ctypes) and tools with clang (Windows/MSVC target or POSIX).
# Usage: bash c/build.sh            -> build/fable.dll (or libfable.so)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$ROOT/build"
mkdir -p "$OUT"
CC="${CC:-/d/LLVM/bin/clang}"
[ -x "$CC" ] || CC=clang
CFLAGS="-O3 -std=c11 -Wall -Wextra -mavx2 -D_CRT_SECURE_NO_WARNINGS"
SRCS="$HERE/fable_p.c $HERE/fable_aead.c $HERE/fable_p_avx2.c $HERE/fable_stream_avx2.c"

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    "$CC" $CFLAGS -DFABLE_BUILD_DLL -shared $SRCS -o "$OUT/fable.dll"
    echo "built $OUT/fable.dll" ;;
  *)
    "$CC" $CFLAGS -fPIC -shared $SRCS -o "$OUT/libfable.so"
    echo "built $OUT/libfable.so" ;;
esac
