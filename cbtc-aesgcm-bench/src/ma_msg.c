#include "ma_msg.h"

#include <string.h>

static void put_u16_be(uint8_t *dst, uint16_t value)
{
	dst[0] = (uint8_t)(value >> 8);
	dst[1] = (uint8_t)value;
}

static void put_u32_be(uint8_t *dst, uint32_t value)
{
	dst[0] = (uint8_t)(value >> 24);
	dst[1] = (uint8_t)(value >> 16);
	dst[2] = (uint8_t)(value >> 8);
	dst[3] = (uint8_t)value;
}

static uint16_t get_u16_be(const uint8_t *src)
{
	return (uint16_t)(((uint16_t)src[0] << 8) | src[1]);
}

static uint32_t get_u32_be(const uint8_t *src)
{
	return ((uint32_t)src[0] << 24) |
	       ((uint32_t)src[1] << 16) |
	       ((uint32_t)src[2] << 8) |
	       (uint32_t)src[3];
}

int ma_msg_size_supported(size_t len)
{
	return len >= MA_MIN_LEN && len <= MA_MAX_LEN;
}

static uint64_t splitmix64_next(uint64_t *state)
{
	uint64_t z = (*state += UINT64_C(0x9E3779B97F4A7C15));

	z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
	z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
	return z ^ (z >> 31);
}

static uint32_t bounded_u32(uint64_t *state, uint32_t min, uint32_t max)
{
	uint32_t range = max - min + 1U;

	return min + (uint32_t)(splitmix64_next(state) % range);
}

static int generate_with_length(
	uint64_t seed,
	ma_msg_t *msg,
	size_t msg_len
)
{
	uint64_t state = seed;
	size_t index;

	if (msg == NULL || !ma_msg_size_supported(msg_len)) {
		return -1;
	}

	memset(msg, 0, sizeof(*msg));
	msg->h.msg_len = (uint16_t)msg_len;
	msg->h.seq = bounded_u32(&state, 1U, UINT32_MAX);
	msg->h.msg_type = (uint8_t)bounded_u32(
		&state, MA_MSG_TYPE_MIN, MA_MSG_TYPE_MAX);
	msg->t.train_id = bounded_u32(
		&state, MA_TRAIN_ID_MIN, MA_TRAIN_ID_MAX);
	msg->t.status = (uint8_t)bounded_u32(
		&state, MA_STATUS_MIN, MA_STATUS_MAX);
	msg->a.data_len = (uint16_t)(msg_len - MA_DATA_OFFSET);

	for (index = 0U; index < msg->a.data_len; ++index) {
		if ((index & 7U) == 0U) {
			state = splitmix64_next(&state);
		}
		msg->a.data[index] = (uint8_t)(state >> ((index & 7U) * 8U));
	}

	return 0;
}

int ma_msg_generate(uint64_t seed, ma_msg_t *msg)
{
	return generate_with_length(seed, msg, MA_GENERATED_LEN);
}

int ma_msg_build(uint64_t seed, size_t msg_len, uint8_t *out)
{
	ma_msg_t msg;

	if (out == NULL || !ma_msg_size_supported(msg_len)) {
		return -1;
	}
	if (generate_with_length(seed, &msg, msg_len) != 0) {
		return -1;
	}

	return ma_msg_serialize(&msg, out, msg_len);
}

int ma_msg_serialize(const ma_msg_t *msg, uint8_t *out, size_t out_len)
{
	if (msg == NULL || out == NULL ||
	    !ma_msg_size_supported(msg->h.msg_len) ||
	    out_len < msg->h.msg_len ||
	    msg->a.data_len != msg->h.msg_len - MA_DATA_OFFSET) {
		return -1;
	}

	put_u16_be(out + MA_MSG_LEN_OFFSET, msg->h.msg_len);
	put_u32_be(out + MA_SEQ_OFFSET, msg->h.seq);
	out[MA_MSG_TYPE_OFFSET] = msg->h.msg_type;
	put_u32_be(out + MA_TRAIN_ID_OFFSET, msg->t.train_id);
	out[MA_STATUS_OFFSET] = msg->t.status;
	put_u16_be(out + MA_DATA_LEN_OFFSET, msg->a.data_len);
	memcpy(out + MA_DATA_OFFSET, msg->a.data, msg->a.data_len);

	return 0;
}

int ma_deserialize(const uint8_t *buf, size_t total_len, ma_msg_t *m)
{
	uint16_t msg_len;
	uint16_t data_len;

	if (buf == NULL || m == NULL || !ma_msg_size_supported(total_len)) {
		return -1;
	}

	msg_len = get_u16_be(buf + MA_MSG_LEN_OFFSET);
	data_len = get_u16_be(buf + MA_DATA_LEN_OFFSET);
	if (msg_len != total_len || data_len != total_len - MA_DATA_OFFSET) {
		return -1;
	}

	m->h.msg_len = msg_len;
	m->h.seq = get_u32_be(buf + MA_SEQ_OFFSET);
	m->h.msg_type = buf[MA_MSG_TYPE_OFFSET];
	m->t.train_id = get_u32_be(buf + MA_TRAIN_ID_OFFSET);
	m->t.status = buf[MA_STATUS_OFFSET];
	m->a.data_len = data_len;
	memcpy(m->a.data, buf + MA_DATA_OFFSET, data_len);

	return 0;
}
