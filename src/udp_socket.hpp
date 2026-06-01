// Thin RAII wrapper around a blocking IPv4 UDP socket with timeout support.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

class UdpSocket {
public:
	int fd = -1;

	UdpSocket();
	~UdpSocket();

	UdpSocket(const UdpSocket&)            = delete;
	UdpSocket& operator=(const UdpSocket&) = delete;

	// Bind to an ephemeral local port on all interfaces.
	void bindAny();

	// Local port the socket is bound to (host byte order).
	uint16_t localPort() const;

	// Resolve `host` and send `data` to host:port. Returns true on full send.
	bool send(const std::vector<uint8_t>& data, const std::string& host, uint16_t port);

	// Receive a datagram, waiting up to `timeoutMs`. Fills senderIp/senderPort.
	// Returns bytes received, or -1 on timeout/error.
	ssize_t recvfromWithTimeout(uint8_t* buf, size_t bufLen, int timeoutMs,
	                            std::string& senderIp, uint16_t& senderPort);
};

// Resolve hostname → first IPv4 address string, or "" on failure.
std::string resolveHost(const std::string& host);
