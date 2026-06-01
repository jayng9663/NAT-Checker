// STUN protocol layer — message construction and parsing.
//
//   RFC 3489  — Classic STUN; CHANGE_REQUEST, CHANGED_ADDRESS, SOURCE_ADDRESS
//               https://datatracker.ietf.org/doc/html/rfc3489
//   RFC 5389  — Modern STUN; Magic Cookie, XOR-MAPPED-ADDRESS, FINGERPRINT (CRC32)
//               https://datatracker.ietf.org/doc/html/rfc5389
//   RFC 5780  — NAT Behavior Discovery; OTHER-ADDRESS, RESPONSE-ORIGIN
//               https://datatracker.ietf.org/doc/html/rfc5780
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <sys/types.h>

// STUN message types (RFC 3489 / 5389)
static constexpr uint16_t STUN_BINDING_REQUEST  = 0x0001;
static constexpr uint16_t STUN_BINDING_RESPONSE = 0x0101;

// STUN attribute types
static constexpr uint16_t STUN_ATTR_MAPPED_ADDRESS      = 0x0001;
static constexpr uint16_t STUN_ATTR_CHANGE_REQUEST      = 0x0003;
static constexpr uint16_t STUN_ATTR_SOURCE_ADDRESS      = 0x0004;
static constexpr uint16_t STUN_ATTR_CHANGED_ADDRESS     = 0x0005;
static constexpr uint16_t STUN_ATTR_XOR_MAPPED_ADDRESS  = 0x0020;
// RFC 5389 attributes
static constexpr uint16_t STUN_ATTR_SOFTWARE            = 0x8022;
static constexpr uint16_t STUN_ATTR_FINGERPRINT         = 0x8028;
// RFC 5780 attributes (NAT Behavior Discovery — replaces 3489 source/changed)
static constexpr uint16_t STUN_ATTR_RESPONSE_ORIGIN     = 0x802b;
static constexpr uint16_t STUN_ATTR_OTHER_ADDRESS       = 0x802c;

static constexpr uint32_t FINGERPRINT_XOR   = 0x5354554eu; // RFC 5389 §15.5
static constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;

// CHANGE_REQUEST flag bits (RFC 3489)
static constexpr uint32_t CHANGE_IP   = 0x00000004;
static constexpr uint32_t CHANGE_PORT = 0x00000002;

// A resolved IPv4 address (host:port) carried in STUN attributes.
struct StunAddress {
	std::string ip;
	uint16_t    port = 0;
	bool        valid = false;

	std::string str() const {
		if (!valid) return "(none)";
		return ip + ":" + std::to_string(port);
	}
	bool operator==(const StunAddress& o) const {
		return ip == o.ip && port == o.port;
	}
	bool operator!=(const StunAddress& o) const {
		return !(*this == o);
	}
};

// Parsed contents of a STUN Binding Response.
struct StunResponse {
	bool         received       = false;
	StunAddress  mappedAddress;
	StunAddress  changedAddress;       // RFC 3489
	StunAddress  sourceAddress;        // RFC 3489
	StunAddress  responseOrigin;       // RFC 5780
	StunAddress  otherAddress;         // RFC 5780
	StunAddress  senderAddr;           // actual UDP sender (from recvfrom)
	std::string  software;             // RFC 5389 SOFTWARE attribute
	bool         fingerprintOk = false; // RFC 5389 FINGERPRINT verified
	uint8_t      txId[12]      = {};
};

// A STUN server endpoint to probe.
struct StunServer {
	std::string host;
	uint16_t    port;
};

// Builds a STUN Binding Request on the wire.
class StunMessage {
public:
	std::vector<uint8_t> data;

	StunMessage(uint16_t msgType, const uint8_t txId[12]);

	// Append a CHANGE_REQUEST attribute (RFC 3489).
	void addChangeRequest(uint32_t flags);

	// Append the FINGERPRINT attribute (RFC 5389 §15.5) — must be last.
	void addFingerprint();
};

// Fill a 12-byte STUN transaction ID with random bytes.
void makeTxId(uint8_t* txId);

// Parse a received STUN datagram. Returns a response with received=false if the
// buffer is not a valid Binding Response matching `expectedTxId`.
StunResponse parseResponse(const uint8_t* buf, ssize_t len, const uint8_t* expectedTxId);
