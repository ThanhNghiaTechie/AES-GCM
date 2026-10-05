#include "ma_crypto.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    const uint8_t key_data[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const uint8_t nonce[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
    };
    const uint8_t plaintext[] = "CBTC AES-GCM abstraction smoke test";
    const size_t plaintext_len = sizeof(plaintext) - 1U;
    uint8_t ciphertext[sizeof(plaintext) - 1U];
    uint8_t tag[16];
    uint8_t decrypted[sizeof(plaintext) - 1U];
    ma_key *key = NULL;
    int result = 1;

    if (ma_crypto_init() != 0) {
        fprintf(stderr, "ma_crypto_init failed\n");
        goto cleanup;
    }
    if (ma_key_setup(&key, key_data, sizeof(key_data)) != 0) {
        fprintf(stderr, "ma_key_setup failed\n");
        goto cleanup;
    }
    if (ma_seal(key, nonce, sizeof(nonce), NULL, 0U,
                plaintext, plaintext_len,
                ciphertext, tag, sizeof(tag)) != 0) {
        fprintf(stderr, "ma_seal failed\n");
        goto cleanup;
    }
    if (ma_open(key, nonce, sizeof(nonce), NULL, 0U,
                ciphertext, plaintext_len, tag, sizeof(tag),
                decrypted) != 0) {
        fprintf(stderr, "ma_open failed\n");
        goto cleanup;
    }
    if (memcmp(plaintext, decrypted, plaintext_len) != 0) {
        fprintf(stderr, "AES-GCM round trip mismatch\n");
        goto cleanup;
    }

    printf("backend: %s (%s)\n",
           ma_crypto_backend_name(),
           ma_crypto_backend_version());
    printf("AES-GCM abstraction smoke test: PASS\n");
    result = 0;

cleanup:
    ma_key_free(key);
    return result;
}
