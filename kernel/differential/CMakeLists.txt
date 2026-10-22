# P2.6 differential experiment: pinned libsecp256k1 v0.8.0 vs the Rust reference.
#
# This is a STANDALONE project. It deliberately does not `add_subdirectory` into
# `kernel/CMakeLists.txt`, is not part of the `zerocoin_kernel` target, and
# nothing here is reachable from `TxSigChecker` or from any node binary.
#
# Build it out-of-tree:
#   cmake -S kernel/differential -B .build/p26-differential -G Ninja
#   cmake --build .build/p26-differential
#   ctest --test-dir .build/p26-differential --output-on-failure
#
# Provenance, defines and the audit trail behind them live in
# `kernel/third_party/secp256k1/ORIGIN.md`.

cmake_minimum_required(VERSION 3.20)

project(zerocoin_secp256k1_differential LANGUAGES C CXX)

# Upstream `v0.8.0` builds as C90 (`CMakeLists.txt:11-13` of that tag). Extensions
# are left at their default exactly as upstream leaves them, so the translation
# unit sees the same dialect it sees in an upstream build.
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

set(SECP256K1_VENDOR_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/secp256k1")

if(NOT EXISTS "${SECP256K1_VENDOR_DIR}/src/secp256k1.c")
  message(FATAL_ERROR
    "Vendored libsecp256k1 not found at ${SECP256K1_VENDOR_DIR}. "
    "See kernel/third_party/secp256k1/ORIGIN.md for the acquisition record.")
endif()

# ---------------------------------------------------------------------------
# The pinned library: exactly three translation units, no optional modules.
# ---------------------------------------------------------------------------
add_library(secp256k1_vendored STATIC
  "${SECP256K1_VENDOR_DIR}/src/secp256k1.c"
  "${SECP256K1_VENDOR_DIR}/src/precomputed_ecmult.c"
  "${SECP256K1_VENDOR_DIR}/src/precomputed_ecmult_gen.c"
)

target_include_directories(secp256k1_vendored PUBLIC "${SECP256K1_VENDOR_DIR}/include")

# ECMULT_WINDOW_SIZE / COMB_BLOCKS / COMB_TEETH are dictated by the shipped
# precomputed tables: changing any of them silently mismatches the table.
# SECP256K1_STATIC is consumer-only and suppresses __declspec(dllimport) on
# Windows, so it must be PUBLIC.
target_compile_definitions(secp256k1_vendored
  PRIVATE
    ECMULT_WINDOW_SIZE=15
    COMB_BLOCKS=43
    COMB_TEETH=6
  PUBLIC
    SECP256K1_STATIC
)

# No optimisation level and no global flag is forced here; the toolchain's
# default for the selected CMAKE_BUILD_TYPE applies, as in an upstream build.
set_target_properties(secp256k1_vendored PROPERTIES
  POSITION_INDEPENDENT_CODE OFF
)

# Third-party warnings are NOT escalated: the vendored tree is a byte-for-byte
# upstream copy and must not be patched to satisfy a local warning policy.
# Only ZeroCoin-authored translation units get the strict treatment.

function(zerocoin_enable_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
endfunction()

# ---------------------------------------------------------------------------
# Test-only harness.
#
# It includes `<zerocoin/sighash.h>` so the `zk::SigVerifier` override is
# checked by the compiler, but it does NOT link `zerocoin_kernel`: no kernel
# object, no transaction parser, no sighash implementation is pulled in.
# ---------------------------------------------------------------------------
add_executable(secp256k1_differential
  "backend/secp256k1_verifier.cpp"
  "runner/main.cpp"
)

target_include_directories(secp256k1_differential PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/backend"
  "${CMAKE_CURRENT_SOURCE_DIR}/../include"
)

target_link_libraries(secp256k1_differential PRIVATE secp256k1_vendored)

zerocoin_enable_warnings(secp256k1_differential)

# ---------------------------------------------------------------------------
# Vector-driven test. The fixture records the Rust verdict for every case; the
# wrapper checks that the runner reproduced it and that no case was skipped.
#
# P2.8 removed the only `--known-divergence` entry. `PublicKey::from_sec1` now
# rejects SEC1 tag 0x05 before the curve is touched, matching libsecp256k1, so
# the whole corpus must agree; `--known-divergence` remains available and the
# wrapper still fails on a stale entry, which is the negative control that keeps
# an allowance from outliving the divergence it was written for.
# ---------------------------------------------------------------------------
find_package(Python3 COMPONENTS Interpreter QUIET)

if(Python3_Interpreter_FOUND)
  enable_testing()
  add_test(
    NAME kernel_secp256k1_differential
    COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/../tools/secp256k1_differential.py"
            --vectors "${CMAKE_CURRENT_SOURCE_DIR}/vectors/ledger.sighash.differential.txt"
            --runner "$<TARGET_FILE:secp256k1_differential>"
            --expect-cases 117
  )
else()
  message(WARNING "Python3 not found: the differential vector test is not registered.")
endif()
