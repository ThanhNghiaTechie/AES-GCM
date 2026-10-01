#ifndef MA_MSG_H
#define MA_MSG_H

#include <stddef.h>
#include <stdint.h>

#define MA_MIN_LEN 16U
#define MA_MAX_LEN 1024U
#define MA_GENERATED_LEN 64U
#define MA_BENCH_LEN_120 120U
#define MA_BENCH_LEN_128 128U
#define MA_BENCH_LEN_256 256U
#define MA_BENCH_LEN_500 500U
#define MA_MSG_TYPE_MIN 1U
#define MA_MSG_TYPE_MAX 3U
#define MA_TRAIN_ID_MIN 1U
#define MA_TRAIN_ID_MAX 999999U
#define MA_STATUS_MIN 0U
#define MA_STATUS_MAX 3U

#define MA_MSG_LEN_OFFSET 0U
#define MA_SEQ_OFFSET 2U
#define MA_MSG_TYPE_OFFSET 6U
#define MA_TRAIN_ID_OFFSET 7U
#define MA_STATUS_OFFSET 11U
#define MA_DATA_LEN_OFFSET 12U
#define MA_DATA_OFFSET 14U
#define MA_BASE_LEN 14U
#define MA_HEADER_LEN 7U
#define MA_TRAIN_LEN 5U
#define MA_AUTHORITY_LEN 2U

typedef struct {
	uint16_t msg_len;
	uint32_t seq;
	uint8_t msg_type;
} ma_header_t;

typedef struct {
	uint32_t train_id;
	uint8_t status;
} ma_train_t;

typedef struct {
	uint16_t data_len;
	uint8_t data[MA_MAX_LEN];
} ma_authority_t;

typedef struct {
	ma_header_t h;
	ma_train_t t;
	ma_authority_t a;
} ma_msg_t;

int ma_msg_size_supported(size_t len);

int ma_msg_generate(
	uint64_t seed,
	ma_msg_t *msg
);

int ma_msg_build(
	uint64_t seed,
	size_t msg_len,
	uint8_t *out
);

int ma_msg_serialize(
	const ma_msg_t *msg,
	uint8_t *out,
	size_t out_len
);

int ma_deserialize(
	const uint8_t *buf,
	size_t total_len,
	ma_msg_t *m
);

#endif /* MA_MSG_H */
