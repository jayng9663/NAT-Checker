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
		case NatType::UdpBlocked:          return "UDP Blocked";
		case NatType::OpenInternet:        return "Open Internet";
		case NatType::FullCone:            return "Full Cone NAT";
		case NatType::RestrictedCone:      return "Restricted NAT";
		case NatType::PortRestrictedCone:  return "Port Restricted NAT";
		case NatType::Symmetric:           return "Symmetric NAT";
		default:                           return "Unknown";
	}
}

const char* natTypeColor(NatType t) {
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

const char* natTypeDescription(NatType t) {
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

// STUN test runner

namespace {

struct TestConfig {
	std::string serverHost;
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

	return StunResponse{};
}

// Primary pool: RFC 3489-capable servers that honor CHANGE_REQUEST.
const std::vector<StunServer> STUN_CANDIDATE_POOL = {
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

// Probe a single STUN server (basic binding only).
ServerProbe probeServer(UdpSocket& sock, const StunServer& srv,
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

} // namespace

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

	// Phase 1: resolve candidates, deduplicate by IP, probe distinct servers
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

	// Phase 2: Cross-check mapped IP:PORT across DISTINCT-IP servers.
	// Check if EITHER the IP or PORT changes across servers. Probing the same
	// physical IP twice always gives the same mapped address even on Symmetric
	// NAT — so those duplicates were excluded in Phase 1.
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

	// Phase 3: Cone-type refinement via RFC 3489 CHANGE_REQUEST.
	// Google/Cloudflare servers (RFC 5389) silently ignore CHANGE_REQUEST, so
	// Phase 3 MUST use RFC 3489-capable servers. We collect up to 3 such servers
	// so Tests II and III can fall back to another if one is down.
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

		// A server confirmed to advertise an alternate address (CHANGED_ADDRESS
		// for RFC 3489, or OTHER_ADDRESS for RFC 5780) and therefore capable of
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

		// Test II: change IP + port — response must come from a DIFFERENT IP.
		//
		// For each ready server (in priority order):
		//   • Timeout         → server appears down, try next server.
		//   • Same-IP reply   → CHANGE_REQUEST silently ignored (RFC 5389), retry
		//                       up to CHANGE_REQ_RETRIES times, then try next server.
		//   • Diff-IP reply   → CHANGE_REQUEST honoured → Full Cone confirmed.
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

		// Test III: change port only — response must come from a DIFFERENT port.
		// Same multi-server fallback strategy as Test II.
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
	auto t1 = std::chrono::steady_clock::now();
	result.timeMs = static_cast<int>(
		std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
	return result;
}
