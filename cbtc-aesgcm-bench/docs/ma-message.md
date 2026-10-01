# MA message format

## Logical fields

`ma_msg_t` contains three C members that represent the four-field MA
specification: a header, train identification/status, and authority data.
The IV and authentication tag are owned by the crypto layer and are not
members of `ma_msg_t`.

| Wire field | C member | Type | Size |
| --- | --- | ---: | ---: |
| Message length | `h.msg_len` | `uint16_t` | 2 bytes |
| Sequence | `h.seq` | `uint32_t` | 4 bytes |
| Message type | `h.msg_type` | `uint8_t` | 1 byte |
| Train ID | `t.train_id` | `uint32_t` | 4 bytes |
| Status | `t.status` | `uint8_t` | 1 byte |
| Authority data length | `a.data_len` | `uint16_t` | 2 bytes |
| Authority data | `a.data` | `uint8_t[]` | `0..1010` bytes |

The serialized field order is exactly the table order:

```text
byte[0..1]   = h.msg_len       (2 bytes, big-endian)
byte[2..5]   = h.seq           (4 bytes, big-endian)
byte[6]      = h.msg_type      (1 byte)
byte[7..10]  = t.train_id      (4 bytes, big-endian)
byte[11]     = t.status        (1 byte)
byte[12..13] = a.data_len      (2 bytes, big-endian)
byte[14..L-1] = a.data         (L - 14 bytes)
```

The fixed metadata size is 14 bytes. Serialization uses these explicit
offsets and does not serialize compiler padding or the in-memory struct
representation. In particular, `memcpy(buffer, &msg, sizeof(msg))` is not a
valid serialization method.

## Encoding and limits

- Integer fields use unsigned types and big-endian (network) byte order.
- `MA_MIN_LEN` is 16 and `MA_MAX_LEN` is 1024; every integer length in this
  inclusive range is supported.
- A message shorter than 16 bytes or longer than 1024 bytes is rejected by
  `ma_msg_build`, `ma_msg_serialize`, and `ma_deserialize`.
- For a valid total length `L`, `a.data_len` must equal `L - 14`. The unused
	tail of the fixed-size in-memory array is not serialized.
- `ma_msg_generate` always creates the deterministic 64-byte benchmark
	profile (`MA_GENERATED_LEN`).

## Deterministic generation profile

`ma_msg_generate(seed, msg)` clears the destination and maps successive
SplitMix64 values into these application ranges:

| Field | Range / value | Meaning |
| --- | --- | --- |
| `h.msg_len` | exactly `64` | Generated benchmark message size |
| `h.seq` | `1..UINT32_MAX` | Non-zero message sequence |
| `h.msg_type` | `1..3` | Defined message type codes |
| `t.train_id` | `1..999999` | Positive train identifier |
| `t.status` | `0..3` | Four status codes |
| `a.data_len` | exactly `50` | `64 - MA_DATA_OFFSET` |
| `a.data[i]` | `0..255` | Deterministic authority payload byte |

The authority payload is intentionally opaque benchmark data. OSRD is not
linked or embedded; a higher-level adapter may replace this payload with
route or speed-limit values while preserving this message API.

## Benchmark sizes

`ma_msg_build(seed, msg_len, out)` supports the full range 16..1024. The
following four sizes are the primary benchmark profiles:

| Requested size | Base MA | Extension/padding | Serialized size |
| ---: | ---: | ---: | ---: |
| 120 | 14 bytes | 106 bytes | 120 bytes |
| 128 | 14 bytes | 114 bytes | 128 bytes |
| 256 | 14 bytes | 242 bytes | 256 bytes |
| 500 | 14 bytes | 486 bytes | 500 bytes |

The first 14 bytes are always the fixed MA metadata. The remaining bytes are
the deterministic authority extension/payload; no new MA field is introduced.
For every requested length `L > 14`, the extension length is exactly `L - 14`
bytes and is stored in `a.data`. Thus, for example, 128 bytes means 14 bytes
of base MA plus 114 deterministic payload bytes, while 1024 bytes means 14
bytes of base MA plus 1010 deterministic payload bytes. The caller must
provide an `out` buffer large enough for the requested size.

## Deterministic generation

`ma_msg_generate` uses the supplied 64-bit seed and the SplitMix64 generator:

```text
z = (state += 0x9E3779B97F4A7C15)
z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
z = (z ^ (z >> 27)) * 0x94D049BB133111EB
output = z ^ (z >> 31)
```

The generated values fill `seq`, `msg_type`, `train_id`, `status`, and
authority data in that order. The same seed produces the same complete
message on every supported platform.
