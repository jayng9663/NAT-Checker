#include "output.hpp"

#include "colors.hpp"

#include <iomanip>
#include <iostream>

#ifndef NATCHECK_VERSION
#define NATCHECK_VERSION "dev"
#endif

void printBanner() {
	std::cout << "\n";
	std::cout << CLR_BOLD CLR_CYAN;
	std::cout << "  ╔═══════════════════════════════════════╗\n";
	std::cout << "  ║            NAT Type Checker           ║\n";
	std::cout << "  ║   RFC 3489 / RFC 5389 / RFC 5780      ║\n";
	std::cout << "  ╚═══════════════════════════════════════╝\n";
	std::cout << CLR_RESET;
	std::cout << CLR_BLUE "  v" NATCHECK_VERSION CLR_RESET "\n\n";
}

void printResult(const NatCheckResult& r) {
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

void printUsage(const char* prog) {
	std::cout << "Usage: " << prog << " [OPTIONS]\n\n"
		<< "Options:\n"
		<< "  -s, --server <host>  Custom STUN server (probed in addition to defaults)\n"
		<< "  -p, --port   <port>  Custom STUN server port (default: 3478)\n"
		<< "  -v, --verbose        Show per-test details\n"
		<< "  -h, --help           Show this help\n"
		<< "      --version        Show version and exit\n\n"
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
