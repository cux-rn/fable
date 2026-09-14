#!/usr/bin/env bash
# Build and run every language example; each must print "RESULT: ALL OK".
# Toolchain locations for this machine can be overridden through the environment.
set -u
cd "$(dirname "$0")"
CC="${CC:-clang}"; CXX="${CXX:-clang++}"
JAVA_HOME="${JAVA_HOME:-}"
JAVAC="${JAVAC:-${JAVA_HOME:+$JAVA_HOME/bin/}javac}"; JAVA="${JAVA:-${JAVA_HOME:+$JAVA_HOME/bin/}java}"
GO="${GO:-go}"; RUSTC="${RUSTC:-rustc}"; LUA="${LUA:-lua}"; NODE="${NODE:-node}"; DOTNET="${DOTNET:-dotnet}"
fail=0
run() { echo "== $1"; shift; if "$@" | tail -1 | grep -q "ALL OK"; then echo "   ALL OK"; else echo "   FAILED"; fail=1; fi; }

( cd c   && $CC  -O2 -std=c11   -D_CRT_SECURE_NO_WARNINGS fable_example.c   -o fable_example ) && run "C"   ./c/fable_example
( cd cpp && $CXX -O2 -std=c++17 fable_example.cpp -o fable_example ) && run "C++" ./cpp/fable_example
( cd java && "$JAVAC" FableExample.java ) && run "Java" "$JAVA" -cp java FableExample
run "Lua" $LUA lua/fable.lua
( cd go && $GO build -o fable_go fable.go ) && run "Go" ./go/fable_go
( cd rust && $RUSTC -O fable.rs -o fable_rs ) && run "Rust" ./rust/fable_rs
run "JavaScript" $NODE js/fable.js
run "C#" $DOTNET run --project csharp -c Release --nologo
run "Python (reference)" python -c "import sys,os; sys.path.insert(0,'..'); import subprocess; r=subprocess.run([sys.executable,'../test_fable.py'],capture_output=True,text=True); print('RESULT: ALL OK' if 'OK' in r.stdout and 'Error' not in r.stdout+r.stderr else 'FAIL')"
exit $fail
