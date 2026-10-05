#ifndef CRYPTO_BACKEND_H
#define CRYPTO_BACKEND_H

#include <psa/crypto.h>

typedef struct ma_key {
	psa_key_id_t key_id;
} crypto_key_t;

#endif /* CRYPTO_BACKEND_H */
