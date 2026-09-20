#ifndef MA_CRYPTO_H
#define MA_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

typedef struct ma_key ma_key;

int ma_crypto_init(void);

int ma_key_setup(
    ma_key **k,
    const uint8_t *key,
    size_t key_len
);

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

void ma_key_free(ma_key *k);

const char *ma_crypto_backend_name(void);
const char *ma_crypto_backend_version(void);
int ma_crypto_has_hw_accel(void);

#endif