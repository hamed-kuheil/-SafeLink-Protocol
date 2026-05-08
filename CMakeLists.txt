# ==============================================================================
# SafeLink Protocol - CMakeLists.txt
# ==============================================================================
# WHY CMake? CMake is the de-facto standard build system generator for modern
# C++ projects. It generates native build files (Makefiles, Ninja, MSVC .sln)
# from a single declarative configuration, enabling cross-platform builds
# without changing a single line of source code.
# ==============================================================================

cmake_minimum_required(VERSION 3.20)
# WHY 3.20+? We need features like cmake_path(), improved FindOpenSSL with
# imported targets, and first-class C++20 support. Anything below 3.15 lacks
# proper target-based dependency propagation (target_link_libraries semantics).

project(
    SafeLinkProtocol
    VERSION 1.0.0
    DESCRIPTION "P2P LAN Encryptor with Hybrid RSA/AES-GCM Security"
    LANGUAGES CXX
)

# ==============================================================================
# SECTION 1: Global C++ Standard Configuration
# ==============================================================================
# WHY set it at the global level AND per-target?
# Setting CMAKE_CXX_STANDARD as a fallback default ensures that any third-party
# subdirectory added later also compiles under C++17. The per-target
# target_compile_features() call is the AUTHORITATIVE, modern way to enforce
# the standard because it propagates correctly through the dependency graph.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# WHY disable extensions? GNU/MSVC extensions introduce non-portable behaviour.
# Disabling them forces strict ISO compliance, which is critical for a
# cryptographic application where undefined behaviour is a security risk.
set(CMAKE_CXX_EXTENSIONS OFF)

# ==============================================================================
# SECTION 2: Build Type & Compiler Hardening Flags
# ==============================================================================
# Default to Release if the user did not specify. In academic/production
# projects you want optimisations active unless explicitly debugging.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

message(STATUS "[SafeLink] Build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "[SafeLink] Compiler   : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")

# Compiler-specific hardening flags.
# WHY separate GCC/Clang from MSVC? Their flag namespaces are entirely different.
# We also add security-hardening flags (-fstack-protector-strong, -D_FORTIFY_SOURCE)
# because this is a network security application — defence-in-depth applies even
# to the compiler level.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall                    # Enable all standard warnings
        -Wextra                  # Enable extra warnings beyond -Wall
        -Wpedantic               # Strict ISO conformance warnings
        -Wshadow                 # Warn when a local var shadows an outer var
        -Wconversion             # Warn on implicit narrowing conversions
        -Wno-unused-parameter    # Silence unused-param noise in stubs
        $<$<CONFIG:Release>:-O2>                   # Optimise for speed
        $<$<CONFIG:Release>:-fstack-protector-strong> # Stack smashing protection
        $<$<CONFIG:Release>:-D_FORTIFY_SOURCE=2>   # Detect buffer overflows at runtime
        $<$<CONFIG:Debug>:-g3>                     # Maximum debug info
        $<$<CONFIG:Debug>:-fsanitize=address,undefined> # ASan + UBSan in debug
    )
    # Linker flags for sanitisers (must mirror compile flags)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_link_options(-fsanitize=address,undefined)
    endif()
elseif(MSVC)
    add_compile_options(
        /W4           # High warning level
        /WX           # Treat warnings as errors
        /permissive-  # Strict standards conformance
        /sdl          # Additional Security Development Lifecycle checks
        $<$<CONFIG:Release>:/O2>
        $<$<CONFIG:Debug>:/Od /Zi>
    )
endif()

# ==============================================================================
# SECTION 3: Dependency Discovery
# ==============================================================================

# --- 3a. OpenSSL ---
# WHY OpenSSL? It is the most battle-tested, FIPS-certifiable open-source
# cryptographic library. It provides RSA, AES-GCM, SHA-256, and the EVP
# (envelope) API which abstracts algorithm selection at runtime.
#
# FindOpenSSL provides two IMPORTED targets (available since CMake 3.4):
#   OpenSSL::SSL   — libssl (TLS handshake state machine)
#   OpenSSL::Crypto — libcrypto (symmetric & asymmetric primitives)
# We link against OpenSSL::Crypto only; we implement our own framing rather
# than using TLS to demonstrate the cryptographic primitives directly.
find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    message(STATUS "[SafeLink] OpenSSL    : ${OPENSSL_VERSION} @ ${OPENSSL_INCLUDE_DIR}")
else()
    message(FATAL_ERROR "[SafeLink] OpenSSL not found. Install libssl-dev (Debian/Ubuntu) or openssl-devel (RHEL/Fedora).")
endif()

# --- 3b. Threads ---
# WHY find_package(Threads)? On POSIX systems this sets -lpthread. On Windows
# it is a no-op because threads are part of the Win32 API. Using the imported
# target Threads::Threads is portable and avoids hard-coding -lpthread.
find_package(Threads REQUIRED)

# --- 3c. Optional: Boost.Asio (header-only async networking) ---
# We use Boost.Asio in header-only mode (BOOST_ASIO_STANDALONE is NOT set
# because we want Boost system_error integration). If Boost is not found,
# we fall back to raw POSIX sockets in NetworkManager.cpp.
# WHY optional? On some lab machines Boost may not be installed; the project
# must still compile, just without the async I/O back-end.
find_package(Boost 1.74 QUIET COMPONENTS system)
if(Boost_FOUND)
    message(STATUS "[SafeLink] Boost.Asio : ${Boost_VERSION} (async networking ENABLED)")
    add_compile_definitions(SAFELINK_USE_BOOST_ASIO)
else()
    message(STATUS "[SafeLink] Boost.Asio : NOT FOUND — falling back to POSIX sockets")
endif()

# ==============================================================================
# SECTION 4: Source File Lists
# ==============================================================================
# WHY list sources explicitly rather than using GLOB? CMake's documentation
# warns that GLOB does not re-run CMake when new files are added, causing
# silent build failures. Explicit lists are the recommended practice.

set(SAFELINK_SOURCES
    src/main.cpp
    src/NetworkManager.cpp
    src/SecurityManager.cpp
    src/ProtocolHandler.cpp
    src/Logger.cpp
)

set(SAFELINK_HEADERS
    include/NetworkManager.hpp
    include/SecurityManager.hpp
    include/ProtocolHandler.hpp
    include/Logger.hpp
)

# ==============================================================================
# SECTION 5: Main Executable Target
# ==============================================================================
add_executable(safelink ${SAFELINK_SOURCES} ${SAFELINK_HEADERS})

# WHY target_compile_features over set(CMAKE_CXX_STANDARD)?
# target_compile_features propagates requirements through the dependency graph.
# If another target links safelink as a library, it will automatically inherit
# the C++17 requirement. This is the Modern CMake idiom.
target_compile_features(safelink PRIVATE cxx_std_17)

# Include directories — PRIVATE because headers are an implementation detail
# of this executable, not a public API consumed by other CMake targets.
target_include_directories(safelink
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${OPENSSL_INCLUDE_DIR}
        $<$<BOOL:${Boost_FOUND}>:${Boost_INCLUDE_DIRS}>
)

# Link libraries using IMPORTED targets (Modern CMake).
# WHY PRIVATE? The executable does not expose these dependencies in its own
# public headers, so transitive propagation is unnecessary and would bloat
# any downstream link lines.
target_link_libraries(safelink
    PRIVATE
        OpenSSL::Crypto          # AES-GCM, RSA, SHA-256 primitives
        Threads::Threads         # std::thread / pthreads
        $<$<BOOL:${Boost_FOUND}>:Boost::system>  # Boost.Asio error handling
)

# On Windows, link against Winsock2 for BSD socket compatibility.
if(WIN32)
    target_link_libraries(safelink PRIVATE ws2_32 mswsock)
    message(STATUS "[SafeLink] Platform   : Windows — linking ws2_32 + mswsock")
else()
    message(STATUS "[SafeLink] Platform   : POSIX (Linux/macOS)")
endif()

# ==============================================================================
# SECTION 6: Compile-time Definitions
# ==============================================================================
# Pass the project version into source code without hard-coding it.
# Accessed in C++ as: SAFELINK_VERSION_MAJOR, SAFELINK_VERSION_MINOR, etc.
target_compile_definitions(safelink
    PRIVATE
        SAFELINK_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
        SAFELINK_VERSION_MINOR=${PROJECT_VERSION_MINOR}
        SAFELINK_VERSION_PATCH=${PROJECT_VERSION_PATCH}
        # Suppress OpenSSL deprecation warnings for EVP API usage on macOS
        $<$<PLATFORM_ID:Darwin>:OPENSSL_API_COMPAT=0x10100000L>
)

# ==============================================================================
# SECTION 7: Test Suite (CTest + standalone test binary)
# ==============================================================================
# WHY CTest integration? It allows `cmake --build . --target test` or
# `ctest --output-on-failure` to run all tests uniformly in CI pipelines.
enable_testing()

add_executable(test_security
    tests/test_security.cpp
    src/SecurityManager.cpp
    src/Logger.cpp
    src/ProtocolHandler.cpp
)

target_compile_features(test_security PRIVATE cxx_std_17)

target_include_directories(test_security
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(test_security
    PRIVATE
        OpenSSL::Crypto
        Threads::Threads
)

if(WIN32)
    target_link_libraries(test_security PRIVATE ws2_32)
endif()

# Register with CTest
add_test(NAME SecurityLayerTests COMMAND test_security)

# ==============================================================================
# SECTION 8: Installation Rules (optional, for packaging)
# ==============================================================================
install(TARGETS safelink
    RUNTIME DESTINATION bin          # Executables
    LIBRARY DESTINATION lib          # Shared libraries (if ever split)
    ARCHIVE DESTINATION lib/static   # Static libraries
)

install(FILES ${SAFELINK_HEADERS} DESTINATION include/safelink)

# ==============================================================================
# SECTION 9: Summary Banner
# ==============================================================================
message(STATUS "")
message(STATUS "╔══════════════════════════════════════════╗")
message(STATUS "║      SafeLink Protocol — Build Config    ║")
message(STATUS "╠══════════════════════════════════════════╣")
message(STATUS "║  Version  : ${PROJECT_VERSION}                       ║")
message(STATUS "║  Standard : C++17                        ║")
message(STATUS "║  OpenSSL  : ${OPENSSL_VERSION}                    ║")
message(STATUS "║  Boost    : ${Boost_FOUND}                    ║")
message(STATUS "╚══════════════════════════════════════════╝")
message(STATUS "")
