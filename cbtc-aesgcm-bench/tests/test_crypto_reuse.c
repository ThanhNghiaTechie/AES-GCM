#include "ma_crypto.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
	const uint8_t key[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
	};
	const uint8_t key128[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	const uint8_t invalid_key[24] = { 0U };
	const uint8_t aad[] = "CBTC authenticated header";
	const uint8_t iv1[12] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01
	};
	const uint8_t iv2[12] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02
	};
	const uint8_t iv3[12] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x03
	};
	const uint8_t invalid_iv[11] = { 0U };
	const size_t valid_tag_lengths[] = { 4U, 8U, 12U, 13U, 14U, 15U, 16U };
	const uint8_t plaintext1[] = "first reusable-key message";
	const uint8_t plaintext2[] = "second reusable-key message";
	const uint8_t plaintext3[] = "third reusable-key message";
	uint8_t altered_aad[sizeof(aad)];
	uint8_t altered_ciphertext1[sizeof(plaintext1) - 1U];
	uint8_t ciphertext1[sizeof(plaintext1) - 1U];
	uint8_t ciphertext2[sizeof(plaintext2) - 1U];
	uint8_t ciphertext3[sizeof(plaintext3) - 1U];
	uint8_t tag1[12];
	uint8_t tag2[16];
	uint8_t tag3[16];
	uint8_t tag_scratch[16];
	uint8_t altered_tag1[sizeof(tag1)];
	uint8_t decrypted1[sizeof(plaintext1) - 1U];
	uint8_t decrypted2[sizeof(plaintext2) - 1U];
	uint8_t decrypted3[sizeof(plaintext3) - 1U];
	uint8_t tampered_plaintext[sizeof(plaintext1) - 1U];
	uint8_t scratch_ciphertext[sizeof(plaintext1) - 1U];
	uint8_t scratch_plaintext[sizeof(plaintext1) - 1U];
	ma_key *key_handle = NULL;
	ma_key *key128_handle = NULL;

	if (ma_crypto_init() != 0) {
		fprintf(stderr, "ma_crypto_init failed\n");
		return 1;
	}
	if (ma_key_setup(&key_handle, key, sizeof(key)) != 0) {
		fprintf(stderr, "ma_key_setup failed\n");
		return 1;
	}
	memcpy(altered_aad, aad, sizeof(aad));
	altered_aad[0] ^= 1U;

	if (ma_seal(key_handle, iv1, sizeof(iv1), aad, sizeof(aad) - 1U,
	            plaintext1, sizeof(plaintext1) - 1U,
	            ciphertext1, tag1, sizeof(tag1)) != 0 ||
	    ma_seal(key_handle, iv2, sizeof(iv2), aad, sizeof(aad) - 1U,
	            plaintext2, sizeof(plaintext2) - 1U,
	            ciphertext2, tag2, sizeof(tag2)) != 0 ||
	    ma_seal(key_handle, iv3, sizeof(iv3), aad, sizeof(aad) - 1U,
	            plaintext3, sizeof(plaintext3) - 1U,
	            ciphertext3, tag3, sizeof(tag3)) != 0 ||
	    ma_open(key_handle, iv1, sizeof(iv1), aad, sizeof(aad) - 1U,
	            ciphertext1, sizeof(ciphertext1), tag1, sizeof(tag1),
	            decrypted1) != 0 ||
	    ma_open(key_handle, iv2, sizeof(iv2), aad, sizeof(aad) - 1U,
	            ciphertext2, sizeof(ciphertext2), tag2, sizeof(tag2),
	            decrypted2) != 0 ||
	    ma_open(key_handle, iv3, sizeof(iv3), aad, sizeof(aad) - 1U,
	            ciphertext3, sizeof(ciphertext3), tag3, sizeof(tag3),
	            decrypted3) != 0) {
		fprintf(stderr, "reusing the key for seal/open failed\n");
		ma_key_free(key_handle);
		return 1;
	}

	if (ma_seal(key_handle, invalid_iv, sizeof(invalid_iv),
	            aad, sizeof(aad) - 1U,
	            plaintext1, sizeof(plaintext1) - 1U,
	            ciphertext1, tag1, sizeof(tag1)) >= 0 ||
	    ma_seal(key_handle, iv1, sizeof(iv1), aad, sizeof(aad) - 1U,
	            plaintext1, sizeof(plaintext1) - 1U,
	            ciphertext1, tag1, 10U) >= 0) {
		fprintf(stderr, "invalid nonce or tag length was accepted\n");
		ma_key_free(key_handle);
		return 1;
	}
	if (ma_open(key_handle, invalid_iv, sizeof(invalid_iv),
	            aad, sizeof(aad) - 1U,
	            ciphertext1, sizeof(ciphertext1), tag1, sizeof(tag1),
	            scratch_plaintext) >= 0 ||
	    ma_open(key_handle, iv1, sizeof(iv1), aad, sizeof(aad) - 1U,
	            ciphertext1, sizeof(ciphertext1), tag1, 10U,
	            scratch_plaintext) >= 0) {
		fprintf(stderr, "open accepted an invalid nonce or tag length\n");
		ma_key_free(key_handle);
		return 1;
	}

	for (size_t i = 0U;
	     i < sizeof(valid_tag_lengths) / sizeof(valid_tag_lengths[0]);
	     ++i) {
		const size_t tag_len = valid_tag_lengths[i];

		if (ma_seal(key_handle, iv1, sizeof(iv1), aad, sizeof(aad) - 1U,
		            plaintext1, sizeof(plaintext1) - 1U,
		            scratch_ciphertext, tag_scratch, tag_len) != 0 ||
		    ma_open(key_handle, iv1, sizeof(iv1), aad, sizeof(aad) - 1U,
		            scratch_ciphertext, sizeof(scratch_ciphertext),
		            tag_scratch, tag_len, scratch_plaintext) != 0 ||
		    memcmp(scratch_plaintext, plaintext1,
		           sizeof(scratch_plaintext)) != 0) {
			fprintf(stderr, "round trip failed for %zu-byte GCM tag\n",
			        tag_len);
			ma_key_free(key_handle);
			return 1;
		}
	}

	memset(tampered_plaintext, 0xA5, sizeof(tampered_plaintext));
	if (ma_open(key_handle, iv1, sizeof(iv1),
	            altered_aad, sizeof(altered_aad) - 1U,
	            ciphertext1, sizeof(ciphertext1), tag1, sizeof(tag1),
	            tampered_plaintext) >= 0) {
		fprintf(stderr, "modified AAD was not rejected\n");
		ma_key_free(key_handle);
		return 1;
	}

	memcpy(altered_ciphertext1, ciphertext1, sizeof(ciphertext1));
	altered_ciphertext1[0] ^= 1U;
	memset(tampered_plaintext, 0xA5, sizeof(tampered_plaintext));
	if (ma_open(key_handle, iv1, sizeof(iv1), aad, sizeof(aad) - 1U,
	            altered_ciphertext1, sizeof(altered_ciphertext1),
	            tag1, sizeof(tag1), tampered_plaintext) >= 0) {
		fprintf(stderr, "modified ciphertext was not rejected\n");
		ma_key_free(key_handle);
		return 1;
	}
	for (size_t i = 0U; i < sizeof(tampered_plaintext); ++i) {
		if (tampered_plaintext[i] != 0U) {
			fprintf(stderr, "plaintext was not cleared after ciphertext failure\n");
			ma_key_free(key_handle);
			return 1;
		}
	}

	memcpy(altered_tag1, tag1, sizeof(tag1));
	altered_tag1[0] ^= 1U;
	memset(tampered_plaintext, 0xA5, sizeof(tampered_plaintext));
	if (ma_open(key_handle, iv1, sizeof(iv1), aad, sizeof(aad) - 1U,
	            ciphertext1, sizeof(ciphertext1),
	            altered_tag1, sizeof(altered_tag1),
	            tampered_plaintext) >= 0) {
		fprintf(stderr, "invalid authentication tag was not rejected\n");
		ma_key_free(key_handle);
		return 1;
	}
	for (size_t i = 0U; i < sizeof(tampered_plaintext); ++i) {
		if (tampered_plaintext[i] != 0U) {
			fprintf(stderr, "plaintext was not cleared after tag failure\n");
			ma_key_free(key_handle);
			return 1;
		}
	}

	ma_key_free(key_handle);

	if (memcmp(decrypted1, plaintext1, sizeof(decrypted1)) != 0 ||
	    memcmp(decrypted2, plaintext2, sizeof(decrypted2)) != 0 ||
	    memcmp(decrypted3, plaintext3, sizeof(decrypted3)) != 0) {
		fprintf(stderr, "reused-key round trip mismatch\n");
		return 1;
	}

	if (ma_key_setup(&key128_handle, key128, sizeof(key128)) != 0 ||
	    ma_seal(key128_handle, iv1, sizeof(iv1), aad, sizeof(aad) - 1U,
	            plaintext1, sizeof(plaintext1) - 1U,
	            ciphertext1, tag1, sizeof(tag1)) != 0 ||
	    ma_open(key128_handle, iv1, sizeof(iv1), aad, sizeof(aad) - 1U,
	            ciphertext1, sizeof(ciphertext1), tag1, sizeof(tag1),
	            decrypted1) != 0) {
		fprintf(stderr, "AES-128 key setup or round trip failed\n");
		ma_key_free(key128_handle);
		return 1;
	}
	ma_key_free(key128_handle);

	if (memcmp(decrypted1, plaintext1, sizeof(decrypted1)) != 0 ||
	    ma_key_setup(&key128_handle, invalid_key, sizeof(invalid_key)) == 0 ||
	    key128_handle != NULL) {
		fprintf(stderr, "AES-128 result or invalid key length check failed\n");
		ma_key_free(key128_handle);
		return 1;
	}

	printf("crypto key reuse: PASS\n");
	return 0;
}
