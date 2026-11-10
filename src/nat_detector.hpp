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
	SymmetricUdpFirewall,
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
	std::string resolvedIp; // the IP the request was actually sent to
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
	// True when filtering was tested with CHANGE-REQUEST (Tests II/III).
	// False when no server advertising a second address was reachable; the
	// type is then the most cautious guess (Port Restricted NAT or Symmetric
	// UDP Firewall), not a measured result.
	bool                     filteringTested = false;
};

// Servers used for the mapping comparison (Phase 1/2). Any RFC 5389 server works.
const std::vector<StunServer>& mappingServerPool();

// Servers tried for CHANGE-REQUEST tests. Only those that advertise
// CHANGED-ADDRESS (RFC 3489) or OTHER-ADDRESS (RFC 5780) are used.
const std::vector<StunServer>& changeRequestServerPool();

// Run the full NAT detection. If `useCustom`, `customHost`:`customPort` is probed
// first, ahead of the built-in server pools.
NatCheckResult checkNat(const std::string& customHost, uint16_t customPort,
                        bool verbose, bool useCustom);
