cmake_minimum_required(VERSION 3.16)

project(nat_check
	VERSION 1.0.0
	DESCRIPTION "RFC-compliant NAT type detection for Linux"
	LANGUAGES CXX)

# --- Options ---------------------------------------------------------------
option(NATCHECK_STATIC "Link the binary statically (portable releases)" OFF)

# Version string baked into the binary. CI overrides this with the git tag,
# e.g. -DNATCHECK_VERSION=1.2.3
set(NATCHECK_VERSION "${PROJECT_VERSION}" CACHE STRING "Version string for --version")

# --- Target ----------------------------------------------------------------
add_executable(nat_check
	src/main.cpp
	src/output.cpp
	src/nat_detector.cpp
	src/udp_socket.cpp
	src/stun.cpp
	src/crc32.cpp)

target_compile_features(nat_check PRIVATE cxx_std_17)

target_compile_definitions(nat_check PRIVATE
	NATCHECK_VERSION="${NATCHECK_VERSION}")

target_compile_options(nat_check PRIVATE
	-Wall -Wextra)

if(NATCHECK_STATIC)
	# Fully static binary so releases run on any Linux distro regardless of
	# its glibc/libstdc++ version.
	target_link_options(nat_check PRIVATE -static -static-libgcc -static-libstdc++)
endif()

# --- Install ---------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS nat_check RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
