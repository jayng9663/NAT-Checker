// NAT type detection (RFC 3489 algorithm + RFC 5780 behavior discovery).
#pragma once

#include <string>
#include <vector>

#include "stun.hpp"

static constexpr int DEFAULT_TIMEOUT_MS = 1000;
static constexpr int MAX_RETRIES        = 3;

enum class NatType {
	Unknown,
	UdpBlocked,
	OpenInternet,
	FullCone,
	RestrictedCone,
	PortRestrictedCone,
	Symmetric
};

const char* natTypeName(NatType t);
const char* natTypeColor(NatType t);
const char* natTypeDescription(NatType t);

// Result of probing a single STUN server.
struct ServerProbe {
	StunServer  server;
	std::string resolvedIp; // actual IP the hostname resolved to
	bool        reachable  = false;
	StunAddress mappedAddr;
	int         latencyMs  = 0;
};

// Full NAT check result.
struct NatCheckResult {
	NatType                  type = NatType::Unknown;
	StunAddress              publicAddr;
	StunAddress              localAddr;
	std::vector<ServerProbe> probes;
	int                      timeMs = 0;
};

// Run the full NAT detection. If `useCustom`, `customHost`:`customPort` is probed
// first, ahead of the built-in server pool.
NatCheckResult checkNat(const std::string& customHost, uint16_t customPort,
                        bool verbose, bool useCustom);
