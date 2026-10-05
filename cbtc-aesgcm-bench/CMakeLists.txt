cmake_minimum_required(VERSION 3.20)

project(cbtc_aesgcm_bench
    VERSION 0.1.0
    LANGUAGES C
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CRYPTO_BACKEND "OPENSSL"
    CACHE STRING "Crypto backend: OPENSSL or MBEDTLS"
)

set_property(CACHE CRYPTO_BACKEND PROPERTY STRINGS
    OPENSSL
    MBEDTLS
)

string(TOUPPER "${CRYPTO_BACKEND}" CRYPTO_BACKEND)

message(STATUS "Crypto backend: ${CRYPTO_BACKEND}")


if(CRYPTO_BACKEND STREQUAL "OPENSSL")

    find_package(OpenSSL REQUIRED)

    set(CRYPTO_SOURCE
        src/crypto/crypto_openssl.c
    )

elseif(CRYPTO_BACKEND STREQUAL "MBEDTLS")

    find_package(MbedTLS REQUIRED)

    set(CRYPTO_SOURCE
        src/crypto/crypto_mbedtls_psa.c
    )

else()

    message(FATAL_ERROR
        "Unsupported CRYPTO_BACKEND=${CRYPTO_BACKEND}. "
        "Use OPENSSL or MBEDTLS."
    )

endif()

add_library(ma_core
    src/ma_msg.c
    src/ma_stats.c
    ${CRYPTO_SOURCE}
)

target_include_directories(ma_core
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

enable_testing()

add_executable(test_serialize
    tests/test_serialize.c
)

target_link_libraries(test_serialize
    PRIVATE
        ma_core
)

add_test(NAME test_serialize COMMAND test_serialize)

add_executable(test_crypto_reuse
    tests/test_crypto_reuse.c
)

target_link_libraries(test_crypto_reuse
    PRIVATE
        ma_core
)

add_test(NAME test_crypto_reuse COMMAND test_crypto_reuse)

add_executable(smoke_crypto
    apps/smoke_crypto.c
)

target_link_libraries(smoke_crypto
    PRIVATE
        ma_core
)

if(CRYPTO_BACKEND STREQUAL "OPENSSL")

    target_link_libraries(ma_core
        PUBLIC
            OpenSSL::Crypto
    )

elseif(CRYPTO_BACKEND STREQUAL "MBEDTLS")

    target_link_libraries(ma_core
        PUBLIC
            MbedTLS::mbedcrypto
    )

endif()