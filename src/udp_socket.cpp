#include "udp_socket.hpp"

#include <cstring>
#include <stdexcept>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>

UdpSocket::UdpSocket() {
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) throw std::runtime_error("socket() failed");
	// Allow port reuse
	int opt = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}

UdpSocket::~UdpSocket() {
	if (fd >= 0) close(fd);
}

void UdpSocket::bindAny() {
	sockaddr_in addr{};
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port        = 0;
	if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
		throw std::runtime_error("bind() failed");
}

uint16_t UdpSocket::localPort() const {
	sockaddr_in addr{};
	socklen_t   len = sizeof(addr);
	getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len);
	return ntohs(addr.sin_port);
}

bool UdpSocket::send(const std::vector<uint8_t>& data, const std::string& host, uint16_t port) {
	struct addrinfo hints{}, *res = nullptr;
	hints.ai_family   = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	std::string portStr = std::to_string(port);
	if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0) return false;
	ssize_t sent = sendto(fd, data.data(), data.size(), 0, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return sent == static_cast<ssize_t>(data.size());
}

ssize_t UdpSocket::recvfromWithTimeout(uint8_t* buf, size_t bufLen, int timeoutMs,
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

std::string resolveHost(const std::string& host) {
	struct addrinfo hints{}, *ai = nullptr;
	hints.ai_family = AF_INET;
	if (getaddrinfo(host.c_str(), nullptr, &hints, &ai) != 0) return "";
	std::string ip = inet_ntoa(reinterpret_cast<sockaddr_in*>(ai->ai_addr)->sin_addr);
	freeaddrinfo(ai);
	return ip;
}
