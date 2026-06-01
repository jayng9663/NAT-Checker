// NAT Type Checker for Linux — CLI entry point.
//
// Detects the local NAT type by speaking STUN (RFC 3489 / 5389 / 5780) to a
// pool of public STUN servers. See README.md for protocol details.

#include "colors.hpp"
#include "nat_detector.hpp"
#include "output.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

#ifndef NATCHECK_VERSION
#define NATCHECK_VERSION "dev"
#endif

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
		} else if (a == "--version") {
			std::cout << "nat_check " NATCHECK_VERSION "\n";
			return 0;
		} else if ((a == "-s" || a == "--server") && i + 1 < argc) {
			customHost = argv[++i];
			useCustom  = true;
		} else if ((a == "-p" || a == "--port") && i + 1 < argc) {
			int port = std::atoi(argv[++i]);
			if (port < 1 || port > 65535) {
				std::cerr << "Invalid port: " << argv[i] << " (must be 1-65535)\n";
				return 1;
			}
			customPort = static_cast<uint16_t>(port);
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
