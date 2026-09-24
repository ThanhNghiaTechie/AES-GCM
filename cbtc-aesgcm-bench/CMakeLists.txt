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

    add_executable(smoke_psa
        apps/smoke_psa.c
    )

    target_link_libraries(smoke_psa
        PRIVATE
            MbedTLS::mbedcrypto
    )

endif()