// Terminal rendering of the banner, usage text, and detection result.
#pragma once

#include "nat_detector.hpp"

void printBanner();
void printUsage(const char* prog);
void printResult(const NatCheckResult& r);
