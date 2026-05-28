/*
 * NAT Type Checker for Linux
 * Implements RFC 3489 (Classic STUN) + RFC 5389 (Modern STUN) + RFC 5780 (NAT Behavior Discovery)
 *
 * Protocol Notes:
 *   RFC 3489  — Classic STUN; CHANGE_REQUEST, CHANGED_ADDRESS, SOURCE_ADDRESS
 *	  https://datatracker.ietf.org/doc/html/rfc3489
 *   RFC 5389  — Modern STUN; mandatory Magic Cookie, XOR-MAPPED-ADDRESS, FINGERPRINT (CRC32)
 *   https://datatracker.ietf.org/doc/html/rfc5389
 *   RFC 5780  — NAT Behavior Discovery over RFC 5389; OTHER-ADDRESS, RESPONSE-ORIGIN
 *   https://datatracker.ietf.org/doc/html/rfc5780
 *
 * NAT Types Detected:
 *   - Open Internet       (no NAT)
 *   - Full Cone NAT
 *   - Restricted NAT
 *   - Port Restricted NAT
 *   - Symmetric NAT
 *   - UDP Blocked
 *
 * Build:
 *   g++ -o nat_check nat_check.cpp
 *
 * Run e.g.
 *   ./nat_check
 *   ./nat_check -v
 *   ./nat_check --server stun.l.google.com --port 19302
 */

#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cassert>
#include <string>
#include <vector>
#include <chrono>
#include <stdexcept>
#include <random>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>

// ANSI Colors
#define CLR_RESET   "\033[0m"
#define CLR_BOLD    "\033[1m"
#define CLR_RED     "\033[38;5;167m"
#define CLR_GREEN   "\033[38;5;142m"
#define CLR_YELLOW  "\033[38;5;214m"
#define CLR_CYAN    "\033[38;5;108m"
#define CLR_BLUE    "\033[38;5;109m"

// STUN Constants (RFC 3489 / 5389)
static constexpr uint16_t STUN_BINDING_REQUEST  = 0x0001;
static constexpr uint16_t STUN_BINDING_RESPONSE = 0x0101;

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

static constexpr uint32_t FINGERPRINT_XOR = 0x5354554eu; // RFC 5389 §15.5

static constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;

static constexpr uint32_t CHANGE_IP   = 0x00000004;
static constexpr uint32_t CHANGE_PORT = 0x00000002;

static constexpr int DEFAULT_TIMEOUT_MS = 2000;
static constexpr int MAX_RETRIES        = 3;

// Data Structures
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

struct StunResponse {
	bool         received       = false;
	StunAddress  mappedAddress;
	StunAddress  changedAddress;   // RFC 3489
	StunAddress  sourceAddress;    // RFC 3489
	StunAddress  responseOrigin;   // RFC 5780
	StunAddress  otherAddress;     // RFC 5780
	StunAddress  senderAddr;       // actual UDP sender (from recvfrom)
	std::string  software;         // RFC 5389 SOFTWARE attribute
	bool         fingerprintOk  = false; // RFC 5389 FINGERPRINT verified
	uint8_t      txId[12]       = {};
};

// CRC32 (IEEE 802.3) — used by RFC 5389 FINGERPRINT attribute
static uint32_t crc32(const uint8_t* data, size_t len) {
	uint32_t crc = 0xFFFFFFFFu;
	for (size_t i = 0; i < len; ++i) {
		crc ^= data[i];
		for (int j = 0; j < 8; ++j)
			crc = (crc >> 1) ^ (0xEDB88320u & -(crc & 1u));
	}
	return crc ^ 0xFFFFFFFFu;
}

// STUN Message Builder
class StunMessage {
	public:
		std::vector<uint8_t> data;

		StunMessage(uint16_t msgType, const uint8_t txId[12]) {
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

		void addChangeRequest(uint32_t flags) {
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

		// RFC 5389 §15.5 — FINGERPRINT must be the last attribute.
		// The length field is updated to include the fingerprint attribute BEFORE
		// the CRC32 is computed, as required by the spec.
		void addFingerprint() {
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
};

// STUN Parser
static StunAddress parseAddress(const uint8_t* buf, uint16_t len, bool xorMapped, const uint8_t* /*txId*/) {
	StunAddress addr;
	if (len < 4) return addr;
	uint8_t family = buf[1];
	if (family != 0x01) return addr; // IPv4 only

	uint16_t port;
	uint32_t ip;
	std::memcpy(&port, buf + 2, 2);
	std::memcpy(&ip,   buf + 4, 4);

	// ntohs BEFORE XOR: STUN_MAGIC_COOKIE>>16 is a host-order constant,
	// so port must also be in host order before the XOR. Doing ntohs after
	// (as the original did) produces wrong results on little-endian (x86).
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

static StunResponse parseResponse(const uint8_t* buf, ssize_t len, const uint8_t* expectedTxId) {
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

	const uint8_t* txId = buf + 8;
	const uint8_t* ptr  = buf + 20;
	const uint8_t* end  = buf + 20 + bodyLen;

	resp.received = true;

	while (ptr + 4 <= end) {
		uint16_t attrType, attrLen;
		std::memcpy(&attrType, ptr,     2); attrType = ntohs(attrType);
		std::memcpy(&attrLen,  ptr + 2, 2); attrLen  = ntohs(attrLen);
		ptr += 4;

		if (ptr + attrLen > end) break;

		switch (attrType) {
			case STUN_ATTR_MAPPED_ADDRESS:
				resp.mappedAddress = parseAddress(ptr, attrLen, false, txId);
				break;
			case STUN_ATTR_XOR_MAPPED_ADDRESS:
				resp.mappedAddress = parseAddress(ptr, attrLen, true, txId);
				break;
			case STUN_ATTR_CHANGED_ADDRESS:
				resp.changedAddress = parseAddress(ptr, attrLen, false, txId);
				break;
			case STUN_ATTR_SOURCE_ADDRESS:
				resp.sourceAddress = parseAddress(ptr, attrLen, false, txId);
				break;
			// RFC 5780
			case STUN_ATTR_RESPONSE_ORIGIN:
				resp.responseOrigin = parseAddress(ptr, attrLen, false, txId);
				break;
			case STUN_ATTR_OTHER_ADDRESS:
				resp.otherAddress = parseAddress(ptr, attrLen, false, txId);
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

// UDP Socket Wrapper
class UdpSocket {
	public:
		int fd = -1;

		UdpSocket() {
			fd = socket(AF_INET, SOCK_DGRAM, 0);
			if (fd < 0) throw std::runtime_error("socket() failed");
			// Allow port reuse
			int opt = 1;
			setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
		}

		~UdpSocket() { if (fd >= 0) close(fd); }

		void bindAny() {
			sockaddr_in addr{};
			addr.sin_family      = AF_INET;
			addr.sin_addr.s_addr = INADDR_ANY;
			addr.sin_port        = 0;
			if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
				throw std::runtime_error("bind() failed");
		}

		uint16_t localPort() const {
			sockaddr_in addr{};
			socklen_t   len = sizeof(addr);
			getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len);
			return ntohs(addr.sin_port);
		}

		bool send(const std::vector<uint8_t>& data, const std::string& host, uint16_t port) {
			struct addrinfo hints{}, *res = nullptr;
			hints.ai_family   = AF_INET;
			hints.ai_socktype = SOCK_DGRAM;
			std::string portStr = std::to_string(port);
			if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0) return false;
			ssize_t sent = sendto(fd, data.data(), data.size(), 0, res->ai_addr, res->ai_addrlen);
			freeaddrinfo(res);
			return sent == static_cast<ssize_t>(data.size());
		}

		// Returns bytes received (and fills senderIp/senderPort), or -1 on timeout
		ssize_t recvfromWithTimeout(uint8_t* buf, size_t bufLen, int timeoutMs,
				std::string& senderIp, uint16_t& senderPort) {
			fd_set fds;
			FD_ZERO(&fds);
			FD_SET(fd, &fds);
			timeval tv;
			tv.tv_sec  = timeoutMs / 1000;
			tv.tv_usec = (timeoutMs % 1000) * 1000;
			int ready = select(fd + 1, &fds, nullptr, nullptr, &tv);
			if (ready <= 0) return -1;
			sockaddr_in from{};
			socklen_t   fromLen = sizeof(from);
			ssize_t n = recvfrom(fd, buf, bufLen, 0,
					reinterpret_cast<sockaddr*>(&from), &fromLen);
			if (n > 0) {
				senderIp   = inet_ntoa(from.sin_addr);
				senderPort = ntohs(from.sin_port);
			}
			return n;
		}
};

// STUN Test Runner
static std::mt19937 rng{std::random_device{}()};

static void makeTxId(uint8_t* txId) {
	std::uniform_int_distribution<uint8_t> dist(0, 255);
	for (int i = 0; i < 12; ++i) txId[i] = dist(rng);
}

struct TestConfig {
	std::string serverHost;
	uint16_t    serverPort;
	uint32_t    changeFlags;  // 0 = normal, CHANGE_IP, CHANGE_PORT, CHANGE_IP|CHANGE_PORT
	int         timeoutMs;
	int         retries;
};

static StunResponse runTest(UdpSocket& sock, const TestConfig& cfg, bool verbose = false) {
	uint8_t txId[12];
	makeTxId(txId);

	StunMessage msg(STUN_BINDING_REQUEST, txId);
	if (cfg.changeFlags)
		msg.addChangeRequest(cfg.changeFlags);
	msg.addFingerprint(); // RFC 5389 §15.5

	uint8_t recvBuf[2048];

	for (int attempt = 0; attempt < cfg.retries; ++attempt) {
		if (verbose) {
			std::cout << CLR_BLUE << "  → Sending to " << cfg.serverHost
				<< ":" << cfg.serverPort;
			if (cfg.changeFlags & CHANGE_IP)   std::cout << " [change-IP]";
			if (cfg.changeFlags & CHANGE_PORT) std::cout << " [change-port]";
			std::cout << CLR_RESET << std::endl;
		}

		if (!sock.send(msg.data, cfg.serverHost, cfg.serverPort)) {
			if (verbose) std::cout << CLR_RED << "  ✗ Send failed\n" << CLR_RESET;
			continue;
		}

		std::string senderIp; uint16_t senderPort = 0;
		ssize_t n = sock.recvfromWithTimeout(recvBuf, sizeof(recvBuf),
				cfg.timeoutMs, senderIp, senderPort);
		if (n > 0) {
			StunResponse resp = parseResponse(recvBuf, n, txId);
			if (resp.received) {
				// Record actual UDP sender so callers can verify CHANGE_REQUEST honour
				resp.senderAddr.ip    = senderIp;
				resp.senderAddr.port  = senderPort;
				resp.senderAddr.valid = true;
				if (verbose) {
					std::cout << CLR_GREEN << "  ✓ Response received" << CLR_RESET;
					if (resp.mappedAddress.valid)
						std::cout << " mapped=" << resp.mappedAddress.str();
					if (resp.changedAddress.valid)
						std::cout << " changed=" << resp.changedAddress.str();
					if (resp.otherAddress.valid)
						std::cout << " other=" << resp.otherAddress.str();
					if (!resp.software.empty())
						std::cout << CLR_YELLOW << " [" << resp.software << "]" << CLR_RESET;
					std::cout << (resp.fingerprintOk ? CLR_GREEN " [FP✓]" CLR_RESET
					                                 : "");
					std::cout << " from=" << senderIp << ":" << senderPort << "\n";
				}
				return resp;
			}
		}
		if (verbose && n <= 0)
			std::cout << CLR_YELLOW << "  ✗ Timeout (attempt " << (attempt+1) << ")\n" << CLR_RESET;
	}

	StunResponse empty;
	return empty;
}

// NAT Type Detection (RFC 3489 Algorithm)
enum class NatType {
	Unknown,
	UdpBlocked,
	OpenInternet,
	FullCone,
	RestrictedCone,
	PortRestrictedCone,
	Symmetric
};

static const char* natTypeName(NatType t) {
	switch (t) {
		case NatType::UdpBlocked:          return "UDP Blocked";
		case NatType::OpenInternet:        return "Open Internet";
		case NatType::FullCone:            return "Full Cone NAT";
		case NatType::RestrictedCone:      return "Restricted NAT";
		case NatType::PortRestrictedCone:  return "Port Restricted NAT";
		case NatType::Symmetric:           return "Symmetric NAT";
		default:                           return "Unknown";
	}
}

static const char* natTypeColor(NatType t) {
	switch (t) {
		case NatType::OpenInternet:        return CLR_GREEN;
		case NatType::FullCone:            return CLR_GREEN;
		case NatType::RestrictedCone:      return CLR_YELLOW;
		case NatType::PortRestrictedCone:  return CLR_YELLOW;
		case NatType::Symmetric:           return CLR_RED;
		case NatType::UdpBlocked:          return CLR_RED;
		default:                           return CLR_BLUE;
	}
}

static const char* natTypeDescription(NatType t) {
	switch (t) {
		case NatType::UdpBlocked:
			return "All UDP traffic is blocked. P2P connections impossible.";
		case NatType::OpenInternet:
			return "No NAT. Direct public IP. Ideal for P2P and gaming.";
		case NatType::FullCone:
			return "Once a port is mapped, any external host can reach it.\n"
				"  Best NAT type. P2P works easily.";
		case NatType::RestrictedCone:
			return "External hosts can only send if you've contacted them first.\n"
				"  Good for most P2P (with hole-punching).";
		case NatType::PortRestrictedCone:
			return "Like Restricted NAT but also restricts by port.\n"
				"  P2P possible with hole-punching in most cases.";
		case NatType::Symmetric:
			return "Each destination gets a different mapped IP/port.\n"
				"  P2P with another Symmetric NAT is very difficult.";
		default:
			return "NAT type could not be determined.";
	}
}

//  Server List
struct StunServer {
	std::string host;
	uint16_t    port;
};

// Primary pool: RFC 3489-capable servers that honor CHANGE_REQUEST
static const std::vector<StunServer> STUN_CANDIDATE_POOL = {
	// RFC 3489 Primary Servers
	{ "stun.stunprotocol.org",         3478 },
	{ "stun.antisip.com",              3478 },
	{ "stun.schlund.de",               3478 },
	{ "stun.voipbuster.com",           3478 },
	{ "stun.ekiga.net",                3478 },
	{ "stun.ideasip.com",              3478 },
	{ "stunserver.stunprotocol.org",   3478 },
	// Additional Public STUN Servers
	{ "stun.l.google.com",             19302 }, // Google (RFC 5389, fallback only)
	{ "stun.cloudflare.com",           3478 }   // Cloudflare (RFC 5389, fallback only)
};

// Resolve hostname → first IPv4 address string, or "" on failure.
static std::string resolveHost(const std::string& host) {
	struct addrinfo hints{}, *ai = nullptr;
	hints.ai_family = AF_INET;
	if (getaddrinfo(host.c_str(), nullptr, &hints, &ai) != 0) return "";
	std::string ip = inet_ntoa(reinterpret_cast<sockaddr_in*>(ai->ai_addr)->sin_addr);
	freeaddrinfo(ai);
	return ip;
}

// Per-server probe result
struct ServerProbe {
	StunServer  server;
	std::string resolvedIp; // actual IP the hostname resolved to
	bool        reachable  = false;
	StunAddress mappedAddr;
	int         latencyMs  = 0;
};

// Full NAT check result
struct NatCheckResult {
	NatType                  type = NatType::Unknown;
	StunAddress              publicAddr;
	StunAddress              localAddr;
	std::vector<ServerProbe> probes;
	int                      timeMs = 0;
};

// Probe a single STUN server (basic binding only)
static ServerProbe probeServer(UdpSocket& sock, const StunServer& srv,
		const std::string& resolvedIp, bool verbose) {
	ServerProbe p;
	p.server     = srv;
	p.resolvedIp = resolvedIp;

	auto t0 = std::chrono::steady_clock::now();
	StunResponse resp = runTest(sock,
			{srv.host, srv.port, 0, DEFAULT_TIMEOUT_MS, MAX_RETRIES}, verbose);
	auto t1 = std::chrono::steady_clock::now();

	p.reachable  = resp.received;
	p.mappedAddr = resp.mappedAddress;
	p.latencyMs  = static_cast<int>(
			std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
	return p;
}

// NAT Type Detection
// Strategy:
//   Phase 1 — Resolve each candidate server's IP, deduplicate, build a probe
//             list of servers with DISTINCT destination IPs (critical for
//             Symmetric NAT detection — a Symmetric NAT maps the same port to
//             the same destination, so probing the same IP twice is useless).
//             Needs at least 2 distinct destination IPs.
//   Phase 2 — Cross-check mapped IP:PORT across distinct-IP servers:
//               same IP:port on all  → Cone-type NAT
//               different IP or port → Symmetric NAT
//   Phase 3 — Cone sub-type via RFC 3489 CHANGE_REQUEST (with sender validation).
NatCheckResult checkNat(const std::string& customHost, uint16_t customPort,
		bool verbose, bool useCustom) {
	NatCheckResult result;
	auto t0 = std::chrono::steady_clock::now();

	//  Phase 1: resolve candidates, deduplicate by IP, probe distinct servers
	UdpSocket sock;
	sock.bindAny();
	uint16_t localPort = sock.localPort();

	// Build candidate list (custom first, then pool)
	std::vector<StunServer> candidates;
	if (useCustom) candidates.push_back({customHost, customPort});
	for (const auto& s : STUN_CANDIDATE_POOL) candidates.push_back(s);

	// Resolve and collect servers with unique destination IPs.
	// We need at least 2 distinct IPs for reliable Symmetric NAT detection.
	std::vector<std::pair<StunServer, std::string>> selected; // {server, resolvedIp}
if (verbose)
	std::cout << "\n" CLR_BOLD "Phase 1" CLR_RESET " — Resolving & probing (need 2+ distinct IPs)\n";

for (const auto& cand : candidates) {
	if (selected.size() >= 4) break; // cap at 4 probes
	std::string ip = resolveHost(cand.host);
	if (ip.empty()) {
		if (verbose)
			std::cout << CLR_YELLOW "  ✗ " << cand.host << " — DNS failed\n" CLR_RESET;
		continue;
	}
	// Skip if we already have this IP (would give identical NAT mapping)
	bool duplicate = false;
	for (const auto& sel : selected)
		if (sel.second == ip) { duplicate = true; break; }
	if (duplicate) {
		if (verbose)
			std::cout << CLR_BLUE "  ↷ " << cand.host
				<< " → " << ip << " (duplicate, skipped)\n" CLR_RESET;
		continue;
	}
	if (verbose)
		std::cout << CLR_CYAN "  [" << cand.host << ":" << cand.port
			<< " → " << ip << "]" CLR_RESET "\n";
	ServerProbe p = probeServer(sock, cand, ip, verbose);
	result.probes.push_back(p);
	if (p.reachable) selected.push_back({cand, ip});
	// Stop once we have 2 reachable distinct-IP servers for Phase 2
	// (keep collecting up to 4 for display richness)
}

// Count reachable probes
int reachable = 0;
for (const auto& p : result.probes)
	if (p.reachable) ++reachable;

	if (reachable == 0) {
		result.type = NatType::UdpBlocked;
		goto done;
	}

// Use first reachable mapped address as public address
for (const auto& p : result.probes) {
	if (p.reachable && p.mappedAddr.valid) {
		result.publicAddr = p.mappedAddr;
		break;
	}
}

// Get local outbound IP via dummy UDP connect (no packet sent)
{
	int tmpFd = socket(AF_INET, SOCK_DGRAM, 0);
	if (tmpFd >= 0) {
		sockaddr_in remote{};
		remote.sin_family      = AF_INET;
		remote.sin_port        = htons(53);
		remote.sin_addr.s_addr = inet_addr("8.8.8.8");
		if (connect(tmpFd, reinterpret_cast<sockaddr*>(&remote), sizeof(remote)) == 0) {
			sockaddr_in localSin{};
			socklen_t   slen = sizeof(localSin);
			if (getsockname(tmpFd, reinterpret_cast<sockaddr*>(&localSin), &slen) == 0) {
				std::string ip = inet_ntoa(localSin.sin_addr);
				if (ip != "0.0.0.0") {
					result.localAddr.ip    = ip;
					result.localAddr.port  = localPort;
					result.localAddr.valid = true;
				}
			}
		}
		close(tmpFd);
	}
}

// Open Internet check (RFC 3489 Test I, §10.1):
// If the mapped IP equals the local outbound IP, there is no NAT.
// RFC 3489 specifies IP-only comparison — port is not part of the criterion.
if (result.localAddr.valid && result.publicAddr.valid &&
		result.localAddr.ip == result.publicAddr.ip) {
	result.type = NatType::OpenInternet;
	goto done;
}

//  Phase 2: Cross-check mapped IP:PORT across DISTINCT-IP servers
// Check if EITHER the IP or PORT changes across servers.
// Probing the same physical IP twice always gives the same mapped address
// even on Symmetric NAT — so those duplicates were excluded in Phase 1.
if (verbose)
	std::cout << "\n" CLR_BOLD "Phase 2" CLR_RESET " — Cross-checking mapped IP:port (distinct IPs only)\n";

{
	StunAddress refAddr;
	bool allSame = true;
	int compared = 0;
	for (const auto& p : result.probes) {
		if (!p.reachable || !p.mappedAddr.valid) continue;
		if (verbose)
			std::cout << "  " << p.server.host << " (" << p.resolvedIp
				<< ") → mapped " << p.mappedAddr.str() << "\n";

		if (!refAddr.valid) {
			refAddr = p.mappedAddr;
		} else {
			++compared;
			// Check if EITHER IP or PORT differs
			if (p.mappedAddr.ip != refAddr.ip || p.mappedAddr.port != refAddr.port) {
				allSame = false;
				break;
			}
		}
	}

	if (compared == 0 && verbose)
		std::cout << CLR_YELLOW
			<< "  ⚠ Only 1 distinct destination IP — Symmetric NAT detection unreliable\n"
			<< CLR_RESET;

	if (!allSame) {
		result.type = NatType::Symmetric;
		goto done;  // Symmetric NAT confirmed — skip Phase 3
	}
}

// Phase 3: Cone-type refinement via RFC 3489 CHANGE_REQUEST
// Google/Cloudflare servers (RFC 5389) silently ignore CHANGE_REQUEST, so
// Phase 3 MUST use RFC 3489-capable servers.  We collect up to 3 such
// servers so Tests II and III can fall back to another if one is down.
if (verbose)
	std::cout << "\n" CLR_BOLD "Phase 3" CLR_RESET " — Cone-type refinement via RFC 3489 CHANGE_REQUEST / RFC 5780\n";

{
	// RFC 3489-capable servers that actually honour CHANGE_REQUEST.
	std::vector<StunServer> rfc3489Pool = {
		{ "stun.stunprotocol.org",       3478  },
		{ "stun.antisip.com",            3478  },
		{ "stun.schlund.de",             3478  },
		{ "stun.voipbuster.com",         3478  },
		{ "stun.ekiga.net",              3478  },
		{ "stun.ideasip.com",            3478  },
		{ "stun.voip.blackberry.com",    3478  },
		{ "stun.sipgate.net",            3478  },
		{ "stunserver.stunprotocol.org", 3478  },
	};

	// Prepend the custom server so it is tried first.
	if (useCustom)
		rfc3489Pool.insert(rfc3489Pool.begin(), {customHost, customPort});

	// A server confirmed to advertise an alternate address (CHANGED_ADDRESS for
	// RFC 3489, or OTHER_ADDRESS for RFC 5780) and therefore capable of
	// honouring CHANGE_REQUEST.
	enum class StunProtocol { RFC3489, RFC5780 };
	struct Rfc3489Candidate {
		std::string  host;
		uint16_t     port;
		std::string  resolvedIp;
		StunProtocol protocol = StunProtocol::RFC3489;
	};

	// Collect up to 3 ready servers — more = more resilient Tests II/III.
	static constexpr int MAX_PHASE3_SERVERS  = 3;
	static constexpr int CHANGE_REQ_RETRIES  = 3;

	std::vector<Rfc3489Candidate> ready;

	if (verbose)
		std::cout << CLR_CYAN "  Probing RFC 3489 servers for CHANGE_REQUEST support\n" CLR_RESET;

	for (const auto& s : rfc3489Pool) {
		if (static_cast<int>(ready.size()) >= MAX_PHASE3_SERVERS) break;

		StunResponse r = runTest(sock,
				{s.host, s.port, 0, DEFAULT_TIMEOUT_MS, 1}, verbose);

		if (r.received && (r.changedAddress.valid || r.otherAddress.valid)) {
			// Accept both RFC 3489 (CHANGED_ADDRESS) and RFC 5780 (OTHER_ADDRESS)
			StunProtocol proto  = r.changedAddress.valid ? StunProtocol::RFC3489
			                                             : StunProtocol::RFC5780;
			StunAddress  altAddr = r.changedAddress.valid ? r.changedAddress : r.otherAddress;
			std::string  ip      = resolveHost(s.host);
			ready.push_back({s.host, s.port, ip, proto});
			if (verbose) {
				const char* tag = (proto == StunProtocol::RFC3489) ? "RFC 3489" : "RFC 5780";
				std::cout << CLR_GREEN "  ✓ Ready [" << ready.size() << "/" << MAX_PHASE3_SERVERS
					<< "] " CLR_RESET << s.host << ":" << s.port
					<< " (" << tag << " alt=" << altAddr.str() << ")\n";
			}
		} else if (r.received && !r.changedAddress.valid && !r.otherAddress.valid) {
			if (verbose)
				std::cout << CLR_YELLOW "  ↷ " CLR_RESET << s.host
					<< " — responded but no CHANGED_ADDRESS / OTHER_ADDRESS (RFC 5389-only, skipping)\n";
		}
		// silent timeout: server unreachable, try next
	}

	if (ready.empty()) {
		if (verbose)
			std::cout << CLR_YELLOW
				<< "  ⚠ No RFC 3489 / RFC 5780 server with alternate-address reachable.\n"
				<< "    Use --server <rfc3489-host:port> to force a specific server.\n"
				<< CLR_RESET;
		result.type = NatType::PortRestrictedCone;
		goto done;
	}

	if (verbose)
		std::cout << "  " CLR_BOLD << ready.size()
			<< " server(s) (RFC 3489 / RFC 5780) available for Tests II/III\n" CLR_RESET;

	// -----------------------------------------------------------------------
	// Test II: change IP + port — response must come from a DIFFERENT IP.
	//
	// For each ready server (in priority order):
	//   • Timeout         → server appears down, try next server.
	//   • Same-IP reply   → CHANGE_REQUEST silently ignored (RFC 5389), retry
	//                       up to CHANGE_REQ_RETRIES times, then try next server.
	//   • Diff-IP reply   → CHANGE_REQUEST honoured → Full Cone confirmed.
	// -----------------------------------------------------------------------
	if (verbose)
		std::cout << CLR_CYAN "\n  Test II" CLR_RESET " — change IP+port\n";

	bool test2HonourChanged = false;

	for (const auto& srv : ready) {
		if (verbose)
			std::cout << CLR_BLUE "  → Server: " CLR_RESET
				<< srv.host << ":" << srv.port << "\n";

		bool timedOut   = false;
		bool honoured   = false;
		int  ignoredCnt = 0;

		for (int attempt = 0; attempt < CHANGE_REQ_RETRIES; ++attempt) {
			if (attempt > 0 && verbose)
				std::cout << CLR_YELLOW "  ↻ Retrying Test II (attempt "
					<< (attempt + 1) << "/" << CHANGE_REQ_RETRIES << ")\n" CLR_RESET;

			StunResponse r = runTest(sock,
					{srv.host, srv.port, CHANGE_IP | CHANGE_PORT,
					 DEFAULT_TIMEOUT_MS, MAX_RETRIES},
					verbose);

			if (!r.received) {
				// Timeout — server may be down; skip remaining retries.
				timedOut = true;
				break;
			}

			if (r.senderAddr.valid && !srv.resolvedIp.empty() &&
					r.senderAddr.ip != srv.resolvedIp) {
				// Response arrived from a different IP → CHANGE_REQUEST honoured.
				test2HonourChanged = true;
				honoured = true;
				break;
			}

			// Server replied from the same IP — CHANGE_REQUEST silently ignored.
			++ignoredCnt;
			if (verbose)
				std::cout << CLR_YELLOW
					<< "  ⚠ Attempt " << (attempt + 1)
					<< ": server replied from same IP — CHANGE_REQUEST ignored (RFC 5389)\n"
					<< CLR_RESET;
			sleep(1);
		}

		if (honoured) break; // Full Cone confirmed — no need to try other servers.

		if (timedOut) {
			if (verbose)
				std::cout << CLR_YELLOW "  ✗ " << srv.host
					<< " timed out on Test II — trying next server\n" CLR_RESET;
		} else if (ignoredCnt == CHANGE_REQ_RETRIES) {
			if (verbose)
				std::cout << CLR_YELLOW "  ✗ All " << CHANGE_REQ_RETRIES
					<< " attempts from " << srv.host
					<< " returned same IP — trying next server\n" CLR_RESET;
		}
	}

	if (test2HonourChanged) {
		result.type = NatType::FullCone;
		goto done;
	}

	// -----------------------------------------------------------------------
	// Test III: change port only — response must come from a DIFFERENT port.
	// Same multi-server fallback strategy as Test II.
	// -----------------------------------------------------------------------
	if (verbose)
		std::cout << CLR_CYAN "\n  Test III" CLR_RESET " — change port only\n";

	bool test3HonourChanged = false;

	for (const auto& srv : ready) {
		if (verbose)
			std::cout << CLR_BLUE "  → Server: " CLR_RESET
				<< srv.host << ":" << srv.port << "\n";

		bool timedOut   = false;
		bool honoured   = false;
		int  ignoredCnt = 0;

		for (int attempt = 0; attempt < CHANGE_REQ_RETRIES; ++attempt) {
			if (attempt > 0 && verbose)
				std::cout << CLR_YELLOW "  ↻ Retrying Test III (attempt "
					<< (attempt + 1) << "/" << CHANGE_REQ_RETRIES << ")\n" CLR_RESET;

			StunResponse r = runTest(sock,
					{srv.host, srv.port, CHANGE_PORT, DEFAULT_TIMEOUT_MS, MAX_RETRIES},
					verbose);

			if (!r.received) {
				timedOut = true;
				break;
			}

			if (r.senderAddr.valid &&
					r.senderAddr.ip   == srv.resolvedIp && // same server IP …
					r.senderAddr.port != srv.port) {        // … but a DIFFERENT port
				test3HonourChanged = true;
				honoured = true;
				break;
			}

			++ignoredCnt;
			if (verbose)
				std::cout << CLR_YELLOW
					<< "  ⚠ Attempt " << (attempt + 1)
					<< ": server replied from same port — CHANGE_REQUEST ignored (RFC 5389)\n"
					<< CLR_RESET;
			sleep(1);
		}

		if (honoured) break;

		if (timedOut) {
			if (verbose)
				std::cout << CLR_YELLOW "  ✗ " << srv.host
					<< " timed out on Test III — trying next server\n" CLR_RESET;
		} else if (ignoredCnt == CHANGE_REQ_RETRIES) {
			if (verbose)
				std::cout << CLR_YELLOW "  ✗ All " << CHANGE_REQ_RETRIES
					<< " attempts from " << srv.host
					<< " returned same port — trying next server\n" CLR_RESET;
		}
	}

	if (test3HonourChanged) {
		result.type = NatType::RestrictedCone;
	} else {
		// No server confirmed cone type — classify conservatively.
		result.type = NatType::PortRestrictedCone;
	}
}

done:
auto t1   = std::chrono::steady_clock::now();
result.timeMs = static_cast<int>(
		std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
return result;
}

// Banner
static void printBanner() {
	std::cout << "\n";
	std::cout << CLR_BOLD CLR_CYAN;
	std::cout << "  ╔═══════════════════════════════════════╗\n";
	std::cout << "  ║            NAT Type Checker           ║\n";
	std::cout << "  ║   RFC 3489 / RFC 5389 / RFC 5780      ║\n";
	std::cout << "  ╚═══════════════════════════════════════╝\n";
	std::cout << CLR_RESET "\n";
}

// Result Printer
static void printResult(const NatCheckResult& r) {
	std::cout << "\n";
	std::cout << CLR_BOLD "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" CLR_RESET;
	std::cout << CLR_BOLD "  Server Probe Summary\n" CLR_RESET;
	std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

	for (const auto& p : r.probes) {
		std::string tag = p.server.host + ":" + std::to_string(p.server.port);
		if (p.reachable) {
			std::cout << "  " CLR_GREEN "✓" CLR_RESET " "
				<< std::left << std::setw(30) << tag
				<< " mapped=" CLR_CYAN << p.mappedAddr.str() << CLR_RESET
				<< "  " CLR_BLUE << p.latencyMs << "ms" CLR_RESET "\n";
		} else {
			std::cout << "  " CLR_RED "✗" CLR_RESET " "
				<< std::left << std::setw(30) << tag
				<< CLR_RED " unreachable" CLR_RESET "\n";
		}
	}

	const char* col = natTypeColor(r.type);

	std::cout << "\n" CLR_BOLD "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" CLR_RESET;
	std::cout << CLR_BOLD "  NAT Detection Result\n" CLR_RESET;
	std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

	std::cout << "  NAT Type   : " << col << CLR_BOLD << natTypeName(r.type) << CLR_RESET << "\n";
	std::cout << "  Description: " << natTypeDescription(r.type) << "\n\n";

	if (r.publicAddr.valid)
		std::cout << "  Public IP  : " CLR_CYAN << r.publicAddr.str() << CLR_RESET "\n";
	if (r.localAddr.valid)
		std::cout << "  Local IP   : " CLR_BLUE << r.localAddr.str() << CLR_RESET "\n";
	std::cout << "  Time       : " CLR_BLUE << r.timeMs << " ms" CLR_RESET "\n";

	std::cout << "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

	// P2P compatibility
	std::cout << CLR_BOLD "  P2P / Gaming Compatibility:\n" CLR_RESET;
	switch (r.type) {
		case NatType::OpenInternet:
		case NatType::FullCone:
			std::cout << "  " CLR_GREEN "● Excellent — Open/Full Cone allows easy P2P\n" CLR_RESET;
			break;
		case NatType::RestrictedCone:
		case NatType::PortRestrictedCone:
			std::cout << "  " CLR_YELLOW "◑ Moderate — Hole-punching typically works\n" CLR_RESET;
			break;
		case NatType::Symmetric:
			std::cout << "  " CLR_RED "○ Poor — Symmetric NAT; relay (TURN) often needed\n" CLR_RESET;
			break;
		case NatType::UdpBlocked:
			std::cout << "  " CLR_RED "✗ None — UDP blocked; no P2P possible\n" CLR_RESET;
			break;
		default:
			std::cout << "  " CLR_BLUE "? Unknown\n" CLR_RESET;
			break;
	}

	// Note about RFC 3489 vs 5389
	if (r.type == NatType::RestrictedCone || r.type == NatType::PortRestrictedCone) {
		std::cout << "\n  " CLR_YELLOW "Note:" CLR_RESET
			<< " Cone sub-type detection requires an RFC 3489 server that\n"
			<< "  honours CHANGE_REQUEST. Google/Cloudflare STUN use RFC 5389\n"
			<< "  and ignore that attribute. For exact classification run:\n"
			<< "    " CLR_CYAN "./nat_check --server stun.stunprotocol.org --port 3478\n" CLR_RESET;
	}
	std::cout << "\n";
}

static void printUsage(const char* prog) {
	std::cout << "Usage: " << prog << " [OPTIONS]\n\n"
		<< "Options:\n"
		<< "  -s, --server <host>  Custom STUN server (probed in addition to defaults)\n"
		<< "  -p, --port   <port>  Custom STUN server port (default: 3478)\n"
		<< "  -v, --verbose        Show per-test details\n"
		<< "  -h, --help           Show this help\n\n"
		<< "Default servers (RFC 3489-capable, ordered by priority):\n"
		<< "  stun.stunprotocol.org:3478\n"
		<< "  stun.antisip.com:3478\n"
		<< "  stun.schlund.de:3478\n"
		<< "  stun.voipbuster.com:3478\n\n"
		<< "Examples:\n"
		<< "  " << prog << "\n"
		<< "  " << prog << " -v\n"
		<< "  " << prog << " --server stun.stunprotocol.org --port 3478\n\n";
}

// Main
int main(int argc, char** argv) {
	std::string customHost;
	uint16_t    customPort = 3478;
	bool        verbose    = false;
	bool        useCustom  = false;

	for (int i = 1; i < argc; ++i) {
		std::string a = argv[i];
		if (a == "-h" || a == "--help") {
			printUsage(argv[0]);
			return 0;
		} else if ((a == "-s" || a == "--server") && i + 1 < argc) {
			customHost = argv[++i];
			useCustom  = true;
		} else if ((a == "-p" || a == "--port") && i + 1 < argc) {
			customPort = static_cast<uint16_t>(std::atoi(argv[++i]));
		} else if (a == "-v" || a == "--verbose") {
			verbose = true;
		} else {
			std::cerr << "Unknown option: " << a << "\n";
			printUsage(argv[0]);
			return 1;
		}
	}

	printBanner();

	std::cout << CLR_BOLD "  STUN Servers: " CLR_RESET
		<< "RFC 3489-capable (stun.stunprotocol.org, stun.antisip.com, stun.schlund.de, etc.)\n";
	if (useCustom)
		std::cout << CLR_BOLD "  Custom       : " CLR_RESET << customHost << ":" << customPort << "\n";
	std::cout << CLR_BOLD "  Verbose      : " CLR_RESET << (verbose ? "yes" : "no") << "\n";
	std::cout << "\n  Running detection...\n";

	try {
		NatCheckResult result = checkNat(customHost, customPort, verbose, useCustom);
		printResult(result);
	} catch (const std::exception& ex) {
		std::cerr << CLR_RED "\nError: " << ex.what() << CLR_RESET "\n";
		return 1;
	}

	return 0;
}
