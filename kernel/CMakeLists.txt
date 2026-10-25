# The consensus kernel. Developer and CI only: the shipped node stays the Rust
# binary (docs/migration/03-target-architecture.md §1).
#
# The one third-party dependency is the curve backend: the pinned vendored
# libsecp256k1 v0.8.0 (third_party/secp256k1, ORIGIN.md), linked PRIVATE and
# reached only through src/secp256k1_verifier.cpp behind the zk::SigVerifier
# seam (docs/architecture/INTERFACE_CONTRACTS.md §3).
#
#   cmake -S kernel -B <build dir> -G Ninja
#   cmake --build <build dir>
#   ctest --test-dir <build dir> --output-on-failure
#
# scripts/gate-g1.ps1 does all three and then replays the P0 corpus.

cmake_minimum_required(VERSION 3.20)
# The vendored libsecp256k1 builds as C90, exactly as upstream builds it.
project(zerocoin_kernel LANGUAGES C CXX)

set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

# ---------------------------------------------------------------------------
# The pinned curve backend: exactly three translation units, no optional
# modules. Provenance, defines and the audit trail live in
# third_party/secp256k1/ORIGIN.md. Third-party warnings are NOT escalated: the
# vendored tree is a byte-for-byte upstream copy and must not be patched to
# satisfy a local warning policy.
# ---------------------------------------------------------------------------
set(SECP256K1_VENDOR_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/secp256k1")

add_library(secp256k1_vendored STATIC
  "${SECP256K1_VENDOR_DIR}/src/secp256k1.c"
  "${SECP256K1_VENDOR_DIR}/src/precomputed_ecmult.c"
  "${SECP256K1_VENDOR_DIR}/src/precomputed_ecmult_gen.c"
)

target_include_directories(secp256k1_vendored PUBLIC "${SECP256K1_VENDOR_DIR}/include")

# ECMULT_WINDOW_SIZE / COMB_BLOCKS / COMB_TEETH are dictated by the shipped
# precomputed tables: changing any of them silently mismatches the table.
# SECP256K1_STATIC suppresses __declspec(dllimport) on Windows; consumer-only,
# so it must stay PUBLIC.
target_compile_definitions(secp256k1_vendored
  PRIVATE
    ECMULT_WINDOW_SIZE=15
    COMB_BLOCKS=43
    COMB_TEETH=6
  PUBLIC
    SECP256K1_STATIC
)

set_target_properties(secp256k1_vendored PROPERTIES
  POSITION_INDEPENDENT_CODE OFF
)

add_library(zerocoin_kernel STATIC
  src/hex.cpp
  src/hash.cpp
  src/sha256.cpp
  src/ripemd160.cpp
  src/uint256.cpp
  src/difficulty.cpp
  src/header.cpp
  src/merkle.cpp
  src/varint.cpp
  src/transaction.cpp
  src/script.cpp
  src/sighash.cpp
  src/secp256k1_verifier.cpp
)
target_include_directories(zerocoin_kernel PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
# PRIVATE: the backend is an implementation detail of the kernel; consumers see
# only the zk::SigVerifier seam, whose header forward-declares the context type.
target_link_libraries(zerocoin_kernel PRIVATE secp256k1_vendored)

# Every translation unit, tests included: a warning is an error everywhere.
function(zerocoin_enable_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
endfunction()

zerocoin_enable_warnings(zerocoin_kernel)

enable_testing()

add_executable(kernel_tests
  tests/test_main.cpp
  tests/test_framework.cpp
  tests/test_hex.cpp
  tests/test_hash.cpp
  tests/test_uint256.cpp
  tests/test_difficulty.cpp
  tests/test_header.cpp
  tests/test_merkle.cpp
  tests/test_varint.cpp
  tests/test_transaction.cpp
  tests/test_script.cpp
  tests/test_sighash.cpp
  tests/test_secp256k1.cpp
  tests/test_static_asserts.cpp
)
target_link_libraries(kernel_tests PRIVATE zerocoin_kernel)
target_include_directories(kernel_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
zerocoin_enable_warnings(kernel_tests)

add_executable(kernel_conformance conformance/main.cpp)
target_link_libraries(kernel_conformance PRIVATE zerocoin_kernel)
zerocoin_enable_warnings(kernel_conformance)

add_test(NAME kernel_unit COMMAND kernel_tests)

# The corpus itself is the oracle: the wrapper reads test/vectors, writes a
# fixture, runs kernel_conformance over it and insists every case is replayed.
find_program(PYTHON_EXECUTABLE NAMES python3 python REQUIRED)
add_test(NAME kernel_conformance
  COMMAND ${PYTHON_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/tools/g1_conformance.py
          --vectors ${CMAKE_CURRENT_SOURCE_DIR}/../test/vectors
          --runner $<TARGET_FILE:kernel_conformance>)

# P2 replays the script and sighash vectors; since P2.10 §7 the accepted spend
# case exercises the vendored backend through the production seam. It is a
# separate test so the G1 guard keeps its own count and deferral list.
add_test(NAME kernel_p2_conformance
  COMMAND ${PYTHON_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/tools/p2_conformance.py
          --vectors ${CMAKE_CURRENT_SOURCE_DIR}/../test/vectors
          --runner $<TARGET_FILE:kernel_conformance>)

# P3 replays the six difficulty cases g1_conformance.py names as deferred to G3
# (params, validate_bits, hash_meets_target, required_work, retarget). A separate
# test for the same reason as P2: the G1 guard keeps its own count.
add_test(NAME kernel_p3_conformance
  COMMAND ${PYTHON_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/tools/p3_conformance.py
          --vectors ${CMAKE_CURRENT_SOURCE_DIR}/../test/vectors
          --runner $<TARGET_FILE:kernel_conformance>)

# P3.1 replays the header preimage and identity cases the P3.1A corpus exports.
# That corpus lives in test/p31-vectors, outside the test/vectors root the three
# wrappers above read, so it gets its own --vectors argument and its own test
# entry: nothing historical changes count, and gate-g1.ps1 and gate-p2-6.ps1
# both run the whole ctest set, so this line is the only gate wiring needed.
add_test(NAME kernel_p31_conformance
  COMMAND ${PYTHON_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/tools/p31_conformance.py
          --vectors ${CMAKE_CURRENT_SOURCE_DIR}/../test/p31-vectors
          --runner $<TARGET_FILE:kernel_conformance>)

# P3.2 replays the twenty leaf-level Merkle cases the P3.2B corpus exports. Its
# corpus has its own root, test/p32-vectors, for the same reason P3.1 has one:
# the P0 manifest pins a single source_commit for the 117 historical cases and
# those values were not generated by the code that stamped it. Additive entry
# only — no existing test changes count, and gate-g1.ps1 runs the whole ctest
# set, so this line is the gate wiring.
add_test(NAME kernel_p32_conformance
  COMMAND ${PYTHON_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/tools/p32_conformance.py
          --vectors ${CMAKE_CURRENT_SOURCE_DIR}/../test/p32-vectors
          --runner $<TARGET_FILE:kernel_conformance>)
