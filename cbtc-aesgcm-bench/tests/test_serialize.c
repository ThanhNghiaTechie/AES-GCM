#include "ma_msg.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int messages_equal(const ma_msg_t *left, const ma_msg_t *right)
{
	return left->h.msg_len == right->h.msg_len &&
	       left->h.seq == right->h.seq &&
	       left->h.msg_type == right->h.msg_type &&
	       left->t.train_id == right->t.train_id &&
	       left->t.status == right->t.status &&
	       left->a.data_len == right->a.data_len &&
	       memcmp(left->a.data, right->a.data, left->a.data_len) == 0;
}

int main(void)
{
	uint8_t serialized[MA_MAX_LEN];
	ma_msg_t original;
	ma_msg_t restored;
	size_t length;

	for (length = MA_MIN_LEN; length <= MA_MAX_LEN; ++length) {
		if (ma_msg_build(UINT64_C(0x123456789ABCDEF0), length,
		                 serialized) != 0) {
			return 1;
		}
		if (ma_deserialize(serialized, length, &original) != 0) {
			return 2;
		}
		memset(&restored, 0, sizeof(restored));
		if (ma_msg_serialize(&original, serialized, length) != 0) {
			return 3;
		}
		if (ma_deserialize(serialized, length, &restored) != 0) {
			return 4;
		}
		if (!messages_equal(&original, &restored)) {
			return 5;
		}
		printf("PASS %zu\n", length);
	}

	puts("serialize -> deserialize all sizes: OK");
	return 0;
}
