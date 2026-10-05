#include <psa/crypto.h>
#include <mbedtls/build_info.h>
#include <mbedtls/platform_util.h>

#include "ma_crypto.h"
#include "crypto_backend.h"

#include <stdlib.h>
#include <string.h>

static int valid_tag_len(size_t tag_len)
{
	return tag_len == 4U || tag_len == 8U ||
	       (tag_len >= 12U && tag_len <= 16U);
}

static psa_algorithm_t gcm_algorithm(size_t tag_len)
{
	if (tag_len == 16U) {
		return PSA_ALG_GCM;
	}

	return PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, tag_len);
}

int ma_crypto_init(void)
{
	return psa_crypto_init() == PSA_SUCCESS ? 0 : -1;
}

int ma_key_setup(ma_key **k, const uint8_t *key, size_t key_len)
{
	crypto_key_t *new_key;
	psa_key_id_t key_id = 0U;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;

	if (k == NULL) {
		return -1;
	}
	*k = NULL;

	if (key == NULL || (key_len != 16U && key_len != 32U)) {
		return -1;
	}

	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		return -1;
	}

	new_key = calloc(1, sizeof(*new_key));
	if (new_key == NULL) {
		return -1;
	}

	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attributes, key_len * 8U);
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(
		&attributes,
		PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(
		&attributes,
		PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(PSA_ALG_GCM, 4U));

	status = psa_import_key(&attributes, key, key_len, &key_id);
	psa_reset_key_attributes(&attributes);
	if (status != PSA_SUCCESS) {
		free(new_key);
		return -1;
	}

	new_key->key_id = key_id;
	*k = new_key;
	return 0;
}

void ma_key_free(ma_key *k)
{
	if (k == NULL) {
		return;
	}

	(void)psa_destroy_key(k->key_id);
	k->key_id = PSA_KEY_ID_NULL;
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
	uint8_t *combined;
	size_t combined_len = 0U;
	psa_status_t status;

	if (k == NULL || iv == NULL || iv_len != MA_GCM_NONCE_LEN ||
	    (aad_len > 0U && aad == NULL) ||
	    (pt_len > 0U && (pt == NULL || ct == NULL)) ||
	    tag == NULL || !valid_tag_len(tag_len) ||
	    pt_len > SIZE_MAX - tag_len) {
		return -1;
	}

	combined = malloc(pt_len + tag_len);
	if (combined == NULL) {
		return -1;
	}

	status = psa_aead_encrypt(
		k->key_id,
		gcm_algorithm(tag_len),
		iv,
		iv_len,
		aad,
		aad_len,
		pt,
		pt_len,
		combined,
		pt_len + tag_len,
		&combined_len);
	if (status != PSA_SUCCESS || combined_len != pt_len + tag_len) {
		free(combined);
		return -1;
	}

	if (pt_len > 0U) {
		memcpy(ct, combined, pt_len);
	}
	memcpy(tag, combined + pt_len, tag_len);
	free(combined);
	return 0;
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
	uint8_t *combined;
	size_t plaintext_len = 0U;
	psa_status_t status;

	if (k == NULL || iv == NULL || iv_len != MA_GCM_NONCE_LEN ||
	    (aad_len > 0U && aad == NULL) ||
	    (ct_len > 0U && (ct == NULL || pt == NULL)) ||
	    tag == NULL || !valid_tag_len(tag_len) ||
	    ct_len > SIZE_MAX - tag_len) {
		return -1;
	}

	combined = malloc(ct_len + tag_len);
	if (combined == NULL) {
		return -1;
	}
	if (ct_len > 0U) {
		memcpy(combined, ct, ct_len);
	}
	memcpy(combined + ct_len, tag, tag_len);

	status = psa_aead_decrypt(
		k->key_id,
		gcm_algorithm(tag_len),
		iv,
		iv_len,
		aad,
		aad_len,
		combined,
		ct_len + tag_len,
		pt,
		ct_len,
		&plaintext_len);
	if (status == PSA_ERROR_INVALID_SIGNATURE) {
		if (pt != NULL && ct_len > 0U) {
			mbedtls_platform_zeroize(pt, ct_len);
		}
		free(combined);
		return -1;
	}

	if (status != PSA_SUCCESS || plaintext_len != ct_len) {
		if (pt != NULL && ct_len > 0U) {
			mbedtls_platform_zeroize(pt, ct_len);
		}
		free(combined);
		return -1;
	}

	free(combined);
	return 0;
}

const char *ma_crypto_backend_name(void)
{
	return "Mbed TLS PSA";
}

const char *ma_crypto_backend_version(void)
{
	return MBEDTLS_VERSION_STRING_FULL;
}

int ma_crypto_has_hw_accel(void)
{
	return 0;
}
