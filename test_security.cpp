// =============================================================================
// SafeLink Protocol — tests/test_security.cpp
// =============================================================================
// Full test suite for SecurityManager will be delivered in the next iteration.
// This stub validates Logger and ProtocolHandler framing at this stage.
// =============================================================================

#include "Logger.hpp"
#include "ProtocolHandler.hpp"

#include <cassert>
#include <iostream>

static int tests_run    = 0;
static int tests_passed = 0;

#define ASSERT_TRUE(expr) do {                                            \
    ++tests_run;                                                          \
    if (!(expr)) {                                                        \
        std::cerr << "[FAIL] " #expr " at " __FILE__ ":" << __LINE__ "\n"; \
    } else {                                                              \
        ++tests_passed;                                                   \
        std::cout << "[PASS] " #expr "\n";                               \
    }                                                                     \
} while(false)

void test_logger_basic() {
    SafeLink::Logger::instance().init("test_run.log", SafeLink::LogLevel::TRACE, false);
    LOG_INFO("TestSuite", "Logger basic test — this line should appear in test_run.log");
    LOG_DEBUG("TestSuite", "Debug entry");
    LOG_WARNING("TestSuite", "Warning entry");
}

void test_protocol_roundtrip() {
    using namespace SafeLink;

    // Build a SECURE_MESSAGE packet with a dummy payload.
    std::vector<uint8_t> payload = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    uint64_t sid = ProtocolHandler::generate_session_id();
    auto packet = ProtocolHandler::build_packet(
        FrameType::SECURE_MESSAGE, sid, 1, PacketFlags::NONE, payload);

    ASSERT_TRUE(packet.size() == SAFELINK_HEADER_SIZE + payload.size());

    // Parse it back.
    auto maybe_result = ProtocolHandler::parse_packet(packet);
    ASSERT_TRUE(maybe_result.has_value());
    ASSERT_TRUE(maybe_result->header.magic == SAFELINK_MAGIC);
    ASSERT_TRUE(maybe_result->header.frame_type ==
        static_cast<uint8_t>(FrameType::SECURE_MESSAGE));
    ASSERT_TRUE(maybe_result->payload == payload);
    ASSERT_TRUE(maybe_result->header.session_id == sid);
}

void test_discovery_serialise() {
    using namespace SafeLink;

    DiscoveryPayload orig;
    std::strncpy(orig.node_name.data(), "Alice-Laptop", 12);
    orig.tcp_port = SAFELINK_SESSION_PORT;
    std::strncpy(orig.ipv4_address.data(), "192.168.1.42", 12);
    orig.timestamp = 1749500000ULL;

    auto bytes = ProtocolHandler::serialise(orig);
    auto maybe = ProtocolHandler::deserialise_discovery(bytes);

    ASSERT_TRUE(maybe.has_value());
    ASSERT_TRUE(std::string(maybe->node_name.data()) == "Alice-Laptop");
    ASSERT_TRUE(maybe->tcp_port == SAFELINK_SESSION_PORT);
    ASSERT_TRUE(maybe->timestamp == 1749500000ULL);
}

void test_bad_magic_rejected() {
    using namespace SafeLink;

    std::vector<uint8_t> payload = {0x01};
    auto packet = ProtocolHandler::build_packet(
        FrameType::HEARTBEAT_PING, 0, 1, PacketFlags::NONE, payload);

    // Corrupt the magic bytes.
    packet[0] = 0xDE; packet[1] = 0xAD; packet[2] = 0xBE; packet[3] = 0xEF;

    auto result = ProtocolHandler::parse_packet(packet);
    ASSERT_TRUE(!result.has_value()); // Must be rejected
}

int main() {
    std::cout << "\n=== SafeLink Protocol — Test Suite (Iteration 1) ===\n\n";

    test_logger_basic();
    test_protocol_roundtrip();
    test_discovery_serialise();
    test_bad_magic_rejected();

    std::cout << "\n--- Results: " << tests_passed << "/" << tests_run << " passed ---\n";

    SafeLink::Logger::instance().shutdown();
    return (tests_passed == tests_run) ? 0 : 1;
}
