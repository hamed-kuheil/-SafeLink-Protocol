// =============================================================================
// SafeLink Protocol — src/main.cpp  (Bootstrap / Entry Point)
// =============================================================================
// This file will be fleshed out with the CLI and node orchestration in a
// later iteration. For now it initialises the Logger and prints a banner so
// the project compiles and runs cleanly at this stage.
// =============================================================================

#include "Logger.hpp"
#include "ProtocolHandler.hpp"

#include <iostream>

int main(int argc, char* argv[]) {
    // Initialise the Logger first — before any other subsystem.
    SafeLink::Logger::instance().init(
        "safelink.log",
        SafeLink::LogLevel::DEBUG,
        true   // also mirror to stderr
    );

    LOG_INFO("Main", "SafeLink Protocol v"
        << SAFELINK_VERSION_MAJOR << "."
        << SAFELINK_VERSION_MINOR << "."
        << SAFELINK_VERSION_PATCH
        << " starting up.");

    LOG_DEBUG("Main", "Protocol header size : " << SafeLink::SAFELINK_HEADER_SIZE << " bytes");
    LOG_DEBUG("Main", "Max payload          : " << SafeLink::SAFELINK_MAX_PAYLOAD / 1024 << " KiB");
    LOG_DEBUG("Main", "AES-GCM IV length    : " << SafeLink::AES_GCM_IV_LENGTH << " bytes");
    LOG_DEBUG("Main", "AES-GCM tag length   : " << SafeLink::AES_GCM_TAG_LENGTH << " bytes");

    // Generate a sample session ID to verify OpenSSL RAND_bytes is working.
    uint64_t sid = SafeLink::ProtocolHandler::generate_session_id();
    LOG_INFO("Main", "Sample session ID    : 0x" << std::hex << sid);

    LOG_INFO("Main", "Iteration 1 complete — Logger + ProtocolHandler ready.");
    LOG_INFO("Main", "Awaiting confirmation to proceed to SecurityManager + NetworkManager.");

    SafeLink::Logger::instance().shutdown();
    return 0;
}
