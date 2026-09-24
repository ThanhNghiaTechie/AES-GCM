#ifndef MA_CRYPTO_H
#define MA_CRYPTO_H
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Opaque key object.
 *
 * Implementation details are hidden from applications.
 */
typedef struct ma_key ma_key;

/*
 * Initialize the selected cryptographic backend.
 *
 * Returns:
 *   0  on success
 *  <0 on error
 */
int ma_crypto_init(void);

/*
 * Import/setup an AES key.
 *
 * Parameters:
 *   k       - output key handle
 *   key     - raw key bytes
 *   key_len - key length in bytes
 *
 * Returns:
 *   0  on success
 *  <0 on error
 */
int ma_key_setup(
    ma_key **k,
    const uint8_t *key,
    size_t key_len
);

/*
 * AES-GCM encryption.
 *
 * Parameters:
 *   k       - key handle
 *   iv      - initialization vector
 *   iv_len  - IV length in bytes
 *   aad     - additional authenticated data
 *   aad_len - AAD length in bytes
 *   pt      - plaintext
 *   pt_len  - plaintext length in bytes
 *   ct      - output ciphertext buffer
 *   tag     - output authentication tag
 *   tag_len - authentication tag length in bytes
 *
 * Returns:
 *   0  on success
 *  <0 on error
 */
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
);

/*
 * AES-GCM decryption.
 *
 * Returns:
 *   0  on success
 *  <0 on error
 */
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
);

/*
 * Free a key handle.
 */
void ma_key_free(ma_key *k);

/*
 * Return the selected crypto backend name.
 */
const char *ma_crypto_backend_name(void);

/*
 * Return the selected crypto backend version.
 */
const char *ma_crypto_backend_version(void);

/*
 * Return whether hardware acceleration is available.
 *
 * Returns:
 *   1 if available
 *   0 if unavailable
 *  <0 on error
 */
int ma_crypto_has_hw_accel(void);

#ifdef __cplusplus
}
#endif

#endif /* MA_CRYPTO_H */