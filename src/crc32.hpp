// CRC32 (IEEE 802.3) — used by the RFC 5389 FINGERPRINT attribute.
#pragma once

#include <cstddef>
#include <cstdint>

// Standard reflected CRC32 over `len` bytes of `data`.
uint32_t crc32(const uint8_t* data, size_t len);
