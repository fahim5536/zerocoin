# The dependency-free consensus kernel. Developer and CI only: the shipped node
# stays the Rust binary (docs/migration/03-target-architecture.md §1).
#
#   cmake -S kernel -B <build dir> -G Ninja
#   cmake --build <build dir>
#   ctest --test-dir <build dir> --output-on-failure
#
# scripts/gate-g1.ps1 does all three and then replays the P0 corpus.

cmake_minimum_required(VERSION 3.20)
project(zerocoin_kernel LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

add_library(zerocoin_kernel STATIC
  src/hex.cpp
  src/hash.cpp
  src/sha256.cpp
  src/ripemd160.cpp
  src/uint256.cpp
  src/varint.cpp
  src/transaction.cpp
  src/script.cpp
  src/sighash.cpp
)
target_include_directories(zerocoin_kernel PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

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
  tests/test_varint.cpp
  tests/test_transaction.cpp
  tests/test_script.cpp
  tests/test_sighash.cpp
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

# P2 replays the script and sighash vectors that need no curve backend. It is a
# separate test so the G1 guard keeps its own count and deferral list.
add_test(NAME kernel_p2_conformance
  COMMAND ${PYTHON_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/tools/p2_conformance.py
          --vectors ${CMAKE_CURRENT_SOURCE_DIR}/../test/vectors
          --runner $<TARGET_FILE:kernel_conformance>)
