cmake_minimum_required(VERSION 3.16)

project(nat_check
	VERSION 1.1.0
	DESCRIPTION "RFC-compliant NAT type detection for Linux"
	LANGUAGES CXX)

# --- Options ---------------------------------------------------------------
option(NATCHECK_STATIC "Link the binary statically (portable releases)" OFF)

# Version string baked into the binary. The release workflow passes the tag,
# e.g. -DNATCHECK_VERSION=1.2.3. Otherwise it comes from `git describe` at
# configure time (e.g. 1.1.0-3-gabc1234), falling back to PROJECT_VERSION when
# the source is not a git checkout.
if(NOT NATCHECK_VERSION)
	set(NATCHECK_VERSION "${PROJECT_VERSION}")
	find_package(Git QUIET)
	if(GIT_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
		execute_process(
			COMMAND "${GIT_EXECUTABLE}" describe --tags --dirty --always
			WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
			OUTPUT_VARIABLE _natcheck_git_desc
			OUTPUT_STRIP_TRAILING_WHITESPACE
			RESULT_VARIABLE _natcheck_git_rc
			ERROR_QUIET)
		if(_natcheck_git_rc EQUAL 0 AND _natcheck_git_desc)
			string(REGEX REPLACE "^v" "" NATCHECK_VERSION "${_natcheck_git_desc}")
		endif()
	endif()
endif()
message(STATUS "nat_check version: ${NATCHECK_VERSION}")

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
