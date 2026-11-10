#include "nat_detector.hpp"

#include "colors.hpp"
#include "udp_socket.hpp"

#include <chrono>
#include <iostream>
#include <utility>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// NAT type metadata

const char* natTypeName(NatType t) {
	switch (t) {
		case NatType::UdpBlocked:           return "UDP Blocked";
		case NatType::OpenInternet:         return "Open Internet";
		case NatType::SymmetricUdpFirewall: return "Symmetric UDP Firewall";
		case NatType::FullCone:             return "Full Cone NAT";
		case NatType::RestrictedCone:       return "Restricted NAT";
		case NatType::PortRestrictedCone:   return "Port Restricted NAT";
		case NatType::Symmetric:            return "Symmetric NAT";
		default:                            return "Unknown";
	}
}

const char* natTypeColor(NatType t) {
	switch (t) {
		case NatType::OpenInternet:         return CLR_GREEN;
		case NatType::FullCone:             return CLR_GREEN;
		case NatType::SymmetricUdpFirewall: return CLR_YELLOW;
		case NatType::RestrictedCone:       return CLR_YELLOW;
		case NatType::PortRestrictedCone:   return CLR_YELLOW;
		case NatType::Symmetric:            return CLR_RED;
		case NatType::UdpBlocked:           return CLR_RED;
		default:                            return CLR_BLUE;
	}
}

const char* natTypeDescription(NatType t) {
	switch (t) {
		case NatType::UdpBlocked:
			return "All UDP traffic is blocked. P2P connections impossible.";
		case NatType::OpenInternet:
			return "No NAT and no inbound filtering. Ideal for P2P and gaming.";
		case NatType::SymmetricUdpFirewall:
			return "Public IP, but a firewall only lets in replies from the\n"
				"  address and port you sent to. P2P works with hole-punching.";
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

// Server pools

const std::vector<StunServer>& mappingServerPool() {
	static const std::vector<StunServer> pool = {
		{ "stun.antisip.com",        3478  },
		{ "stun.schlund.de",         3478  },
		{ "stun.voipbuster.com",     3478  },
		{ "stun.ekiga.net",          3478  },
		{ "stun.l.google.com",       19302 }, // RFC 5389 only
		{ "stun.cloudflare.com",     3478  }, // RFC 5389 only
	};
	return pool;
}

const std::vector<StunServer>& changeRequestServerPool() {
	static const std::vector<StunServer> pool = {
		{ "stun.schlund.de",          3478 },
		{ "stun.voipbuster.com",      3478 },
		{ "stun.sipgate.net",         3478 },
		{ "stun.ekiga.net",           3478 },
		{ "stun.antisip.com",         3478 },
		{ "stun.voip.blackberry.com", 3478 },
	};
	return pool;
}

// STUN test runner

namespace {

struct TestConfig {
	std::string label;        // hostname, for log output only
	std::string serverIp;     // resolved IPv4 address the request is sent to
	uint16_t    serverPort;
	uint32_t    changeFlags;  // 0 = normal, CHANGE_IP, CHANGE_PORT, CHANGE_IP|CHANGE_PORT
	int         timeoutMs;
	int         retries;
};

StunResponse runTest(UdpSocket& sock, const TestConfig& cfg, bool verbose) {
	uint8_t txId[12];
	makeTxId(txId);

	StunMessage msg(STUN_BINDING_REQUEST, txId);
	if (cfg.changeFlags)
		msg.addChangeRequest(cfg.changeFlags);
	msg.addFingerprint(); // RFC 5389 §15.5

	uint8_t recvBuf[2048];

	for (int attempt = 0; attempt < cfg.retries; ++attempt) {
		if (verbose) {
			std::cout << CLR_BLUE << "  → Sending to " << cfg.label
				<< " (" << cfg.serverIp << ":" << cfg.serverPort << ")";
			if (cfg.changeFlags & CHANGE_IP)   std::cout << " [change-IP]";
			if (cfg.changeFlags & CHANGE_PORT) std::cout << " [change-port]";
			std::cout << CLR_RESET << std::endl;
		}

		if (!sock.send(msg.data, cfg.serverIp, cfg.serverPort)) {
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

	return StunResponse{};
}

// Probe a single STUN server (basic binding only) at an already-resolved IP.
ServerProbe probeServer(UdpSocket& sock, const StunServer& srv,
		const std::string& resolvedIp, bool verbose) {
	ServerProbe p;
	p.server     = srv;
	p.resolvedIp = resolvedIp;

	auto t0 = std::chrono::steady_clock::now();
	StunResponse resp = runTest(sock,
			{srv.host, resolvedIp, srv.port, 0, DEFAULT_TIMEOUT_MS, MAX_RETRIES}, verbose);
	auto t1 = std::chrono::steady_clock::now();

	p.reachable  = resp.received;
	p.mappedAddr = resp.mappedAddress;
	p.latencyMs  = static_cast<int>(
			std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
	return p;
}

// A server that advertises a second address (CHANGED-ADDRESS for RFC 3489,
// OTHER-ADDRESS for RFC 5780) and can therefore answer CHANGE-REQUEST.
struct ChangeServer {
	std::string host;
	std::string ip;   // resolved once; every test is sent to this exact address
	uint16_t    port;
};

static constexpr int MAX_CHANGE_SERVERS = 3;
static constexpr int CHANGE_REQ_RETRIES = 3;

std::vector<ChangeServer> findChangeServers(UdpSocket& sock,
		const std::string& customHost, uint16_t customPort, bool useCustom, bool verbose) {
	std::vector<StunServer> pool;
	if (useCustom) pool.push_back({customHost, customPort});
	for (const auto& s : changeRequestServerPool()) pool.push_back(s);

	if (verbose)
		std::cout << CLR_CYAN "  Looking for servers that advertise a second address\n" CLR_RESET;

	std::vector<ChangeServer> ready;
	for (const auto& s : pool) {
		if (static_cast<int>(ready.size()) >= MAX_CHANGE_SERVERS) break;

		std::string ip = resolveHost(s.host);
		if (ip.empty()) {
			if (verbose)
				std::cout << CLR_YELLOW "  ✗ " << s.host << " — DNS failed\n" CLR_RESET;
			continue;
		}

		StunResponse r = runTest(sock, {s.host, ip, s.port, 0, DEFAULT_TIMEOUT_MS, 1}, verbose);
		if (!r.received) continue; // silent timeout: try next

		if (r.changedAddress.valid || r.otherAddress.valid) {
			bool        rfc3489 = r.changedAddress.valid;
			StunAddress alt     = rfc3489 ? r.changedAddress : r.otherAddress;
			ready.push_back({s.host, ip, s.port});
			if (verbose)
				std::cout << CLR_GREEN "  ✓ Ready [" << ready.size() << "/" << MAX_CHANGE_SERVERS
					<< "] " CLR_RESET << s.host << " " << ip << ":" << s.port
					<< " (" << (rfc3489 ? "RFC 3489" : "RFC 5780") << " alt=" << alt.str() << ")\n";
		} else if (verbose) {
			std::cout << CLR_YELLOW "  ↷ " CLR_RESET << s.host
				<< " — responded but no CHANGED_ADDRESS / OTHER_ADDRESS (RFC 5389-only, skipping)\n";
		}
	}

	if (ready.empty() && verbose)
		std::cout << CLR_YELLOW
			<< "  ⚠ No RFC 3489 / RFC 5780 server with alternate-address reachable.\n"
			<< "    Use --server <host> --port <port> to force a specific server.\n"
			<< CLR_RESET;
	return ready;
}

// Send CHANGE-REQUEST with `flags` to each ready server in turn. Returns true as
// soon as a reply arrives from the changed address:
//   CHANGE_IP set   → reply source IP differs from the IP the request went to
//   CHANGE_PORT only → same IP, different port
// Per server: a timeout moves on to the next server (the NAT or firewall
// dropped the reply, or the server is down); a reply from the original address
// means the server ignored the flags, so it is retried after 1 s, up to
// CHANGE_REQ_RETRIES times.
bool runChangeTest(UdpSocket& sock, const std::vector<ChangeServer>& ready,
		uint32_t flags, const char* name, bool verbose) {
	if (verbose)
		std::cout << CLR_CYAN "\n  " << name << CLR_RESET
			<< ((flags & CHANGE_IP) ? " — change IP+port\n" : " — change port only\n");

	for (const auto& srv : ready) {
		if (verbose)
			std::cout << CLR_BLUE "  → Server: " CLR_RESET << srv.host
				<< " (" << srv.ip << ":" << srv.port << ")\n";

		bool timedOut = false;
		for (int attempt = 0; attempt < CHANGE_REQ_RETRIES; ++attempt) {
			if (attempt > 0 && verbose)
				std::cout << CLR_YELLOW "  ↻ Retrying " << name << " (attempt "
					<< (attempt + 1) << "/" << CHANGE_REQ_RETRIES << ")\n" CLR_RESET;

			StunResponse r = runTest(sock,
					{srv.host, srv.ip, srv.port, flags, DEFAULT_TIMEOUT_MS, MAX_RETRIES}, verbose);
			if (!r.received) {
				timedOut = true;
				break;
			}

			bool honoured = (flags & CHANGE_IP)
				? r.senderAddr.ip != srv.ip
				: (r.senderAddr.ip == srv.ip && r.senderAddr.port != srv.port);
			if (honoured) return true;

			if (verbose)
				std::cout << CLR_YELLOW << "  ⚠ Attempt " << (attempt + 1)
					<< ": server replied from the same "
					<< ((flags & CHANGE_IP) ? "IP" : "port")
					<< " — CHANGE_REQUEST ignored\n" << CLR_RESET;
			sleep(1);
		}

		if (verbose)
			std::cout << CLR_YELLOW "  ✗ " << srv.host
				<< (timedOut ? " timed out on " : " ignored CHANGE_REQUEST on ")
				<< name << " — trying next server\n" CLR_RESET;
	}
	return false;
}

// Local outbound IP via a UDP connect() (no packet is sent).
StunAddress localOutboundAddr(uint16_t localPort) {
	StunAddress addr;
	int tmpFd = socket(AF_INET, SOCK_DGRAM, 0);
	if (tmpFd < 0) return addr;
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
				addr.ip    = ip;
				addr.port  = localPort;
				addr.valid = true;
			}
		}
	}
	close(tmpFd);
	return addr;
}

} // namespace

// NAT Type Detection
// Strategy:
//   Phase 1 — Resolve each candidate server once, deduplicate by IP, and probe
//             servers with DISTINCT destination IPs (a Symmetric NAT maps the
//             same destination to the same port, so probing one IP twice proves
//             nothing). Every later request goes to the IP resolved here.
//   Open Internet / firewall — if the public IP equals the local IP, Test II
//             tells an open host from a Symmetric UDP Firewall (RFC 3489 §10.1).
//   Phase 2 — Cross-check mapped IP:PORT across distinct-IP servers:
//               same IP:port on all  → Cone-type NAT
//               different IP or port → Symmetric NAT
//   Phase 3 — Cone sub-type via CHANGE-REQUEST (Tests II and III) with
//             reply-source validation.
NatCheckResult checkNat(const std::string& customHost, uint16_t customPort,
		bool verbose, bool useCustom) {
	NatCheckResult result;
	auto t0 = std::chrono::steady_clock::now();

	UdpSocket sock;
	sock.bindAny();
	uint16_t localPort = sock.localPort();

	// Phase 1: resolve candidates, deduplicate by IP, probe distinct servers
	std::vector<StunServer> candidates;
	if (useCustom) candidates.push_back({customHost, customPort});
	for (const auto& s : mappingServerPool()) candidates.push_back(s);

	if (verbose)
		std::cout << "\n" CLR_BOLD "Phase 1" CLR_RESET " — Resolving & probing (need 2+ distinct IPs)\n";

	int reachable = 0;
	for (const auto& cand : candidates) {
		if (reachable >= 4) break; // cap at 4 reachable probes
		std::string ip = resolveHost(cand.host);
		if (ip.empty()) {
			if (verbose)
				std::cout << CLR_YELLOW "  ✗ " << cand.host << " — DNS failed\n" CLR_RESET;
			continue;
		}
		bool duplicate = false;
		for (const auto& p : result.probes)
			if (p.resolvedIp == ip) { duplicate = true; break; }
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
		if (p.reachable) ++reachable;
	}

	if (reachable == 0) {
		result.type = NatType::UdpBlocked;
		result.filteringTested = true;
		goto done;
	}

	for (const auto& p : result.probes) {
		if (p.reachable && p.mappedAddr.valid) {
			result.publicAddr = p.mappedAddr;
			break;
		}
	}

	result.localAddr = localOutboundAddr(localPort);

	// No NAT (RFC 3489 §10.1): mapped IP equals the local IP. Test II then
	// separates an open host from a Symmetric UDP Firewall.
	if (result.localAddr.valid && result.publicAddr.valid &&
		result.localAddr.ip == result.publicAddr.ip) {
		if (verbose)
			std::cout << "\n" CLR_BOLD "No NAT" CLR_RESET " — public IP is local; testing inbound filtering\n";
		std::vector<ChangeServer> ready =
			findChangeServers(sock, customHost, customPort, useCustom, verbose);
		if (ready.empty()) {
			result.type = NatType::SymmetricUdpFirewall; // most cautious, untested
		} else {
			result.filteringTested = true;
			result.type = runChangeTest(sock, ready, CHANGE_IP | CHANGE_PORT, "Test II", verbose)
				? NatType::OpenInternet
				: NatType::SymmetricUdpFirewall;
		}
		goto done;
	}

	// Phase 2: cross-check mapped IP:PORT across distinct-IP servers.
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
				if (p.mappedAddr != refAddr) {
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
			result.filteringTested = true; // filtering is irrelevant here
			goto done;
		}
	}

	// Phase 3: cone sub-type via CHANGE-REQUEST. Google/Cloudflare (RFC 5389)
	// ignore CHANGE-REQUEST, so only servers that advertise a second address
	// are used.
	if (verbose)
		std::cout << "\n" CLR_BOLD "Phase 3" CLR_RESET " — Cone-type refinement via RFC 3489 CHANGE_REQUEST / RFC 5780\n";

	{
		std::vector<ChangeServer> ready =
			findChangeServers(sock, customHost, customPort, useCustom, verbose);
		if (ready.empty()) {
			result.type = NatType::PortRestrictedCone; // most cautious, untested
			goto done;
		}
		result.filteringTested = true;

		if (verbose)
			std::cout << "  " CLR_BOLD << ready.size()
				<< " server(s) (RFC 3489 / RFC 5780) available for Tests II/III\n" CLR_RESET;

		if (runChangeTest(sock, ready, CHANGE_IP | CHANGE_PORT, "Test II", verbose))
			result.type = NatType::FullCone;
		else if (runChangeTest(sock, ready, CHANGE_PORT, "Test III", verbose))
			result.type = NatType::RestrictedCone;
		else
			result.type = NatType::PortRestrictedCone;
	}

done:
	auto t1 = std::chrono::steady_clock::now();
	result.timeMs = static_cast<int>(
		std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
	return result;
}
