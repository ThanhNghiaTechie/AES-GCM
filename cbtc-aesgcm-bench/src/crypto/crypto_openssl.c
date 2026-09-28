#include "ma_crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

struct ma_key {
    uint8_t key[32];
    size_t key_len;
};


int ma_crypto_init(void)
{
    if (OPENSSL_init_crypto(0, NULL) != 1) {
        return -1;
    }

    return 0;
}

int ma_key_setup(
    ma_key **k,
    const uint8_t *key,
    size_t key_len
)
{
    ma_key *new_key;

    if (k == NULL) {
        return -1;
    }

    *k = NULL;

    if (key == NULL || key_len != 32) {
        return -1;
    }

    new_key = calloc(1, sizeof(*new_key));

    if (new_key == NULL) {
        return -1;
    }

    memcpy(new_key->key, key, key_len);
    new_key->key_len = key_len;

    *k = new_key;

    return 0;
}

void ma_key_free(ma_key *k)
{
    if (k == NULL) {
        return;
    }

    OPENSSL_cleanse(k->key, sizeof(k->key));

    free(k);
}

int ma_seal(
    ma_key *k,
    const uint8_t *iv,
    size_t iv_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *pt,
    size_t pt_len,
    uint8_t *ct,
    uint8_t *tag,
    size_t tag_len
)
{
    EVP_CIPHER_CTX *ctx;
    uint8_t final_block[EVP_MAX_BLOCK_LENGTH];
    int len = 0;
    int final_len = 0;
    int result = -1;

    if (k == NULL || k->key_len != sizeof(k->key) ||
        iv == NULL || iv_len == 0 || iv_len > INT_MAX ||
        (aad_len > 0 && aad == NULL) || aad_len > INT_MAX ||
        (pt_len > 0 && (pt == NULL || ct == NULL)) || pt_len > INT_MAX ||
        tag == NULL || tag_len == 0 || tag_len > 16) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, k->key, iv) != 1) {
        goto cleanup;
    }

    if (aad_len > 0 &&
        EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) {
        goto cleanup;
    }

    if (pt_len > 0 &&
        EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) {
        goto cleanup;
    }

    if (EVP_EncryptFinal_ex(ctx, final_block, &final_len) != 1 || final_len != 0) {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_len, tag) != 1) {
        goto cleanup;
    }

    result = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

int ma_open(
    ma_key *k,
    const uint8_t *iv,
    size_t iv_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ct,
    size_t ct_len,
    const uint8_t *tag,
    size_t tag_len,
    uint8_t *pt
)
{
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t final_block[EVP_MAX_BLOCK_LENGTH];
    int len = 0;
    int final_len = 0;
    int plaintext_started = 0;
    int result = -1;

    if (k == NULL || k->key_len != sizeof(k->key) ||
        iv == NULL || iv_len == 0 || iv_len > INT_MAX ||
        (aad_len > 0 && aad == NULL) || aad_len > INT_MAX ||
        (ct_len > 0 && (ct == NULL || pt == NULL)) || ct_len > INT_MAX ||
        tag == NULL || tag_len == 0 || tag_len > 16) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, k->key, iv) != 1) {
        goto cleanup;
    }

    if (aad_len > 0 &&
        EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) {
        goto cleanup;
    }

    if (ct_len > 0) {
        plaintext_started = 1;
        if (EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ct_len) != 1 ||
            len != (int)ct_len) {
            goto cleanup;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (void *)tag) != 1) {
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, final_block, &final_len) <= 0 || final_len != 0) {
        goto cleanup;
    }

    result = 0;

cleanup:
    if (result != 0 && plaintext_started) {
        OPENSSL_cleanse(pt, ct_len);
    }
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

const char *ma_crypto_backend_name(void)
{
    return "OpenSSL";
}

const char *ma_crypto_backend_version(void)
{
    return OpenSSL_version(OPENSSL_VERSION);
}

int ma_crypto_has_hw_accel(void)
{
#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
    const char *cpu_settings = OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS);
    const char *capabilities;
    char *end;
    unsigned long long lv0;
    const unsigned long long required = (1ULL << 33) | (1ULL << 57);

    if (cpu_settings == NULL) {
        return 0;
    }

    capabilities = strstr(cpu_settings, "OPENSSL_ia32cap=");
    if (capabilities == NULL) {
        return 0;
    }
    capabilities += sizeof("OPENSSL_ia32cap=") - 1;

    errno = 0;
    lv0 = strtoull(capabilities, &end, 0);
    if (end == capabilities || errno == ERANGE ||
        (*end != '\0' && *end != ':')) {
        return 0;
    }

    return (lv0 & required) == required ? 1 : 0;
#else
    return 0;
#endif
}
