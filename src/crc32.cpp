#include "crc32.hpp"

uint32_t crc32(const uint8_t* data, size_t len) {
	uint32_t crc = 0xFFFFFFFFu;
	for (size_t i = 0; i < len; ++i) {
		crc ^= data[i];
		for (int j = 0; j < 8; ++j)
			crc = (crc >> 1) ^ (0xEDB88320u & -(crc & 1u));
	}
	return crc ^ 0xFFFFFFFFu;
}
