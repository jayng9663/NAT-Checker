#include "stun.hpp"
#include "crc32.hpp"

#include <cstring>
#include <random>

#include <arpa/inet.h>
#include <netinet/in.h>

// STUN Message Builder

StunMessage::StunMessage(uint16_t msgType, const uint8_t txId[12]) {
	data.resize(20, 0);
	// Message Type
	data[0] = (msgType >> 8) & 0xFF;
	data[1] =  msgType       & 0xFF;
	// Magic Cookie
	data[4] = 0x21; data[5] = 0x12;
	data[6] = 0xA4; data[7] = 0x42;
	// Transaction ID (12 bytes)
	std::memcpy(data.data() + 8, txId, 12);
}

void StunMessage::addChangeRequest(uint32_t flags) {
	uint16_t attrType = htons(STUN_ATTR_CHANGE_REQUEST);
	uint16_t attrLen  = htons(4);
	uint32_t val      = htonl(flags);
	auto pos = data.size();
	data.resize(pos + 8);
	std::memcpy(data.data() + pos,     &attrType, 2);
	std::memcpy(data.data() + pos + 2, &attrLen,  2);
	std::memcpy(data.data() + pos + 4, &val,      4);
	// Update message length field
	uint16_t bodyLen = htons(static_cast<uint16_t>(data.size() - 20));
	std::memcpy(data.data() + 2, &bodyLen, 2);
}

// RFC 5389 §15.5 — FINGERPRINT must be the last attribute. The length field is
// updated to include the fingerprint attribute BEFORE the CRC32 is computed.
void StunMessage::addFingerprint() {
	uint16_t bodyLen = htons(static_cast<uint16_t>(data.size() - 20 + 8));
	std::memcpy(data.data() + 2, &bodyLen, 2);
	uint32_t fp = htonl(crc32(data.data(), data.size()) ^ FINGERPRINT_XOR);
	uint16_t attrType = htons(STUN_ATTR_FINGERPRINT);
	uint16_t attrLen  = htons(4);
	auto pos = data.size();
	data.resize(pos + 8);
	std::memcpy(data.data() + pos,     &attrType, 2);
	std::memcpy(data.data() + pos + 2, &attrLen,  2);
	std::memcpy(data.data() + pos + 4, &fp,       4);
}

// Transaction IDs

static std::mt19937 rng{std::random_device{}()};

void makeTxId(uint8_t* txId) {
	// uint8_t is not a permitted distribution type per [rand.req.genl]; use unsigned.
	std::uniform_int_distribution<unsigned> dist(0, 255);
	for (int i = 0; i < 12; ++i) txId[i] = static_cast<uint8_t>(dist(rng));
}

// STUN Parser

static StunAddress parseAddress(const uint8_t* buf, uint16_t len, bool xorMapped) {
	StunAddress addr;
	// MAPPED-ADDRESS family is IPv4 here: 1 byte reserved + 1 family + 2 port + 4 addr.
	// Require all 8 bytes before dereferencing to avoid reading past the attribute.
	if (len < 8) return addr;
	uint8_t family = buf[1];
	if (family != 0x01) return addr; // IPv4 only

	uint16_t port;
	uint32_t ip;
	std::memcpy(&port, buf + 2, 2);
	std::memcpy(&ip,   buf + 4, 4);

	// ntohs BEFORE XOR: STUN_MAGIC_COOKIE>>16 is a host-order constant, so port
	// must also be in host order before the XOR. Doing ntohs after produces
	// wrong results on little-endian (x86).
	port = ntohs(port);
	if (xorMapped) {
		port ^= static_cast<uint16_t>(STUN_MAGIC_COOKIE >> 16);
		ip   ^= htonl(STUN_MAGIC_COOKIE);
	}
	struct in_addr ia;
	ia.s_addr = ip;

	addr.ip    = inet_ntoa(ia);
	addr.port  = port;
	addr.valid = true;
	return addr;
}

StunResponse parseResponse(const uint8_t* buf, ssize_t len, const uint8_t* expectedTxId) {
	StunResponse resp;
	if (len < 20) return resp;

	uint16_t msgType;
	std::memcpy(&msgType, buf, 2);
	msgType = ntohs(msgType);

	if (msgType != STUN_BINDING_RESPONSE) return resp;

	// Verify transaction ID
	if (std::memcmp(buf + 8, expectedTxId, 12) != 0) return resp;

	uint16_t bodyLen;
	std::memcpy(&bodyLen, buf + 2, 2);
	bodyLen = ntohs(bodyLen);

	const uint8_t* ptr = buf + 20;
	const uint8_t* end = buf + 20 + bodyLen;

	resp.received = true;

	while (ptr + 4 <= end) {
		uint16_t attrType, attrLen;
		std::memcpy(&attrType, ptr,     2); attrType = ntohs(attrType);
		std::memcpy(&attrLen,  ptr + 2, 2); attrLen  = ntohs(attrLen);
		ptr += 4;

		if (ptr + attrLen > end) break;

		switch (attrType) {
			case STUN_ATTR_MAPPED_ADDRESS:
				resp.mappedAddress = parseAddress(ptr, attrLen, false);
				break;
			case STUN_ATTR_XOR_MAPPED_ADDRESS:
				resp.mappedAddress = parseAddress(ptr, attrLen, true);
				break;
			case STUN_ATTR_CHANGED_ADDRESS:
				resp.changedAddress = parseAddress(ptr, attrLen, false);
				break;
			case STUN_ATTR_SOURCE_ADDRESS:
				resp.sourceAddress = parseAddress(ptr, attrLen, false);
				break;
			// RFC 5780
			case STUN_ATTR_RESPONSE_ORIGIN:
				resp.responseOrigin = parseAddress(ptr, attrLen, false);
				break;
			case STUN_ATTR_OTHER_ADDRESS:
				resp.otherAddress = parseAddress(ptr, attrLen, false);
				break;
			// RFC 5389
			case STUN_ATTR_SOFTWARE:
				if (attrLen > 0)
					resp.software.assign(reinterpret_cast<const char*>(ptr), attrLen);
				break;
			case STUN_ATTR_FINGERPRINT: {
				if (attrLen >= 4) {
					uint32_t got; std::memcpy(&got, ptr, 4);
					got = ntohl(got);
					// CRC32 covers message bytes up to (not including) this attribute
					size_t fpStart = static_cast<size_t>(ptr - buf) - 4;
					resp.fingerprintOk = (crc32(buf, fpStart) ^ FINGERPRINT_XOR) == got;
				}
				break;
			}
			default:
				break;
		}

		// Attributes are padded to 4-byte boundary
		uint16_t padded = (attrLen + 3) & ~3;
		ptr += padded;
	}

	return resp;
}
