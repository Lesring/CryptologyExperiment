cmake_minimum_required(VERSION 3.15)
project(tf_psa_builtin_aes_bench C)

set(CMAKE_C_STANDARD 99)

set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(GEN_FILES ON CACHE BOOL "" FORCE)
set(TF_PSA_CRYPTO_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)

add_subdirectory(TF-PSA-Crypto EXCLUDE_FROM_ALL)

add_executable(tf_psa_aes_ecb_bench aes_ecb_bench.c)
target_link_libraries(tf_psa_aes_ecb_bench PRIVATE tfpsacrypto)

target_compile_definitions(tf_psa_aes_ecb_bench PRIVATE MBEDTLS_ALLOW_PRIVATE_ACCESS)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(tf_psa_aes_ecb_bench PRIVATE -O3 -march=native)
endif()
