#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <psa/crypto.h>

int main(void)
{
    psa_status_t status;

    /*
     * AES-128 key: 16 bytes
     */
    const uint8_t key_data[16] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };

    /*
     * 96-bit IV, the standard GCM IV size.
     */
    const uint8_t nonce[12] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b
    };

    const uint8_t plaintext[] = "CBTC AES-GCM PSA smoke test";

    const size_t plaintext_len = sizeof(plaintext) - 1;

    uint8_t ciphertext[sizeof(plaintext) - 1 + 16];
    uint8_t tag[16];

    size_t ciphertext_len = 0;

    psa_key_attributes_t attributes =
        PSA_KEY_ATTRIBUTES_INIT;

    psa_key_id_t key_id = 0;

    /*
     * 1. Initialize PSA Crypto.
     */
    status = psa_crypto_init();

    if (status != PSA_SUCCESS) {
        printf("psa_crypto_init failed: %ld\n",
               (long)status);
        return 1;
    }

    printf("psa_crypto_init: OK\n");

    /*
     * 2. Configure AES-GCM key attributes.
     */
    psa_set_key_type(
        &attributes,
        PSA_KEY_TYPE_AES
    );

    psa_set_key_bits(
        &attributes,
        128
    );

    psa_set_key_usage_flags(
        &attributes,
        PSA_KEY_USAGE_ENCRYPT |
        PSA_KEY_USAGE_DECRYPT
    );

    psa_set_key_algorithm(
        &attributes,
        PSA_ALG_GCM
    );

    /*
     * 3. Import the raw AES key.
     */
    status = psa_import_key(
        &attributes,
        key_data,
        sizeof(key_data),
        &key_id
    );

    /*
     * Attributes are no longer needed.
     */
    psa_reset_key_attributes(&attributes);

    if (status != PSA_SUCCESS) {
        printf("psa_import_key failed: %ld\n",
               (long)status);
        return 1;
    }

    printf("psa_import_key: OK\n");

    /*
     * 4. Encrypt using AES-GCM.
     *
     * Output format:
     *
     * ciphertext || authentication_tag
     */
    status = psa_aead_encrypt(
        key_id,
        PSA_ALG_GCM,
        nonce,
        sizeof(nonce),
        NULL,
        0,
        plaintext,
        plaintext_len,
        ciphertext,
        sizeof(ciphertext),
        &ciphertext_len
    );

    if (status != PSA_SUCCESS) {
        printf("psa_aead_encrypt failed: %ld\n",
               (long)status);

        psa_destroy_key(key_id);
        return 1;
    }

    printf("psa_aead_encrypt: OK\n");
    printf("ciphertext + tag length: %zu bytes\n",
           ciphertext_len);

    /*
     * GCM with a 16-byte tag should produce:
     *
     * ciphertext length + 16-byte authentication tag.
     */
    if (ciphertext_len != plaintext_len + 16) {
        printf("Unexpected output length\n");

        psa_destroy_key(key_id);
        return 1;
    }

    /*
     * Print the generated ciphertext and tag.
     */
    printf("ciphertext + tag: ");

    for (size_t i = 0; i < ciphertext_len; ++i) {
        printf("%02x", ciphertext[i]);
    }

    printf("\n");

    /*
     * 5. Destroy the PSA key.
     */
    status = psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        printf("psa_destroy_key failed: %ld\n",
               (long)status);
        return 1;
    }

    printf("psa_destroy_key: OK\n");
    printf("PSA AES-GCM smoke test: PASS\n");

    return 0;
}