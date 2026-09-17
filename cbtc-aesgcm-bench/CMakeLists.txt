cmake_minimum_required(VERSION 3.16)

project(cbtc-aesgcm-bench C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Chọn thư viện crypto
set(CRYPTO_BACKEND "OPENSSL" CACHE STRING "Crypto backend")
set_property(CACHE CRYPTO_BACKEND PROPERTY STRINGS OPENSSL MBEDTLS)

message(STATUS "Crypto backend: ${CRYPTO_BACKEND}")

# =========================
# Source chung
# =========================

set(COMMON_SOURCES
    src/ma_msg.c
    src/ma_stats.c
    src/timer/timer_posix.c
    src/platform/platform_linux.c
)

# =========================
# Crypto backend
# =========================

if(CRYPTO_BACKEND STREQUAL "OPENSSL")

    find_package(OpenSSL REQUIRED)

    set(CRYPTO_SOURCE
        src/crypto/crypto_openssl.c
    )

    set(CRYPTO_LIBRARIES
        OpenSSL::Crypto
    )

elseif(CRYPTO_BACKEND STREQUAL "MBEDTLS")

    find_package(MbedTLS REQUIRED)

    set(CRYPTO_SOURCE
        src/crypto/crypto_mbedtls_psa.c
    )

    set(CRYPTO_LIBRARIES
        MbedTLS::mbedcrypto
    )

else()

    message(FATAL_ERROR
        "Unsupported CRYPTO_BACKEND: ${CRYPTO_BACKEND}. "
        "Use OPENSSL or MBEDTLS."
    )

endif()

add_library(ma_crypto STATIC
    ${CRYPTO_SOURCE}
)

target_include_directories(ma_crypto
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(ma_crypto
    PUBLIC
        ${CRYPTO_LIBRARIES}
)

# Bench micro

add_executable(bench_micro
    apps/bench_micro.c
    ${COMMON_SOURCES}
)

target_include_directories(bench_micro
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(bench_micro
    PRIVATE
        ma_crypto
)

# =========================
# Bench sweep
# =========================

add_executable(bench_sweep
    apps/bench_sweep.c
    ${COMMON_SOURCES}
)

target_include_directories(bench_sweep
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(bench_sweep
    PRIVATE
        ma_crypto
)