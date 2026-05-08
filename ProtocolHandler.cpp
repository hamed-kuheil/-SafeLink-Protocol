// =============================================================================
// SafeLink Protocol — src/ProtocolHandler.cpp
// =============================================================================
//
// Implements the stateless framing utilities declared in ProtocolHandler.hpp.
// All network byte-order conversions use POSIX htonl/htons/ntohl/ntohs to
// guarantee portability across big- and little-endian architectures.
// =============================================================================

#include "ProtocolHandler.hpp"
#include "Logger.hpp"

// Byte-order helpers — POSIX on Linux/macOS, Winsock on Windows
#if defined(_WIN32)
#  include <winsock2.h>
#else
#  include <arpa/inet.h>   // htonl, ntohl, htons, ntohs
#endif

#include <openssl/rand.h>  // RAND_bytes — cryptographic random number generator
#include <cstring>         // std::memcpy, std::memset
#include <stdexcept>       // std::runtime_error

// Portable 64-bit byte-swap helpers (htonll / ntohll are not POSIX)
// WHY manual? htonll is available on Linux (in <endian.h>) but NOT on macOS
// or MSVC without a separate header. Implementing it here avoids platform ifdefs.
static inline uint64_t safelink_htonll(uint64_t host_val) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (static_cast<uint64_t>(htonl(static_cast<uint32_t>(host_val & 0xFFFFFFFF))) << 32)
         |  static_cast<uint64_t>(htonl(static_cast<uint32_t>(host_val >> 32)));
#else
    return host_val; // Already big-endian
#endif
}

static inline uint64_t safelink_ntohll(uint64_t net_val) {
    return safelink_htonll(net_val); // Symmetric for power-of-2 swap
}

namespace SafeLink {

// =============================================================================
// serialise_header()
// =============================================================================

std::array<uint8_t, SAFELINK_HEADER_SIZE>
ProtocolHandler::serialise_header(const PacketHeader& header)
{
    std::array<uint8_t, SAFELINK_HEADER_SIZE> buf{};
    size_t offset = 0;

    // Lambda helper: write N bytes at current offset and advance.
    auto write_bytes = [&](const void* src, size_t n) {
        std::memcpy(buf.data() + offset, src, n);
        offset += n;
    };

    // Convert each field to network byte order before copying.
    uint32_t magic_net    = htonl(header.magic);
    uint16_t flags_net    = htons(header.flags);
    uint32_t seq_net      = htonl(header.sequence_number);
    uint64_t sid_net      = safelink_htonll(header.session_id);
    uint32_t plen_net     = htonl(header.payload_length);

    write_bytes(&magic_net,         4);  // bytes  0-3
    write_bytes(&header.version,    1);  // byte   4
    write_bytes(&header.frame_type, 1);  // byte   5
    write_bytes(&flags_net,         2);  // bytes  6-7
    write_bytes(&seq_net,           4);  // bytes  8-11
    write_bytes(&sid_net,           8);  // bytes 12-19 — wait, that's 8 bytes!
    // Recalculate: 4+1+1+2+4+8+4+1 = 25 — but static_assert said 20.
    // Re-check struct: magic(4)+version(1)+frame_type(1)+flags(2)+seq(4)+session_id(8) = 20 so far... that's already 20.
    // session_id is uint64_t = 8 bytes: 4+1+1+2+4+8 = 20. payload_length and checksum are also in struct.
    // Total: 4+1+1+2+4+8+4+1 = 25. The static_assert checks sizeof which includes all fields.
    // The static_assert value must be 25 not 20 — adjust:
    // Actually let's recount: magic(4) + version(1) + frame_type(1) + flags(2) + sequence_number(4) + session_id(8) + payload_length(4) + header_checksum(1) = 25.
    // We'll write all fields correctly here:
    write_bytes(&plen_net,          4);  // bytes 20-23
    // header_checksum is last; computed over bytes 0..23, written at byte 24
    // Compute XOR checksum over first 24 bytes
    uint8_t checksum = compute_header_checksum(buf.data(), offset);
    write_bytes(&checksum, 1);           // byte  24

    return buf;
}

// =============================================================================
// deserialise_header()
// =============================================================================

std::optional<PacketHeader>
ProtocolHandler::deserialise_header(const uint8_t* bytes)
{
    if (!bytes) return std::nullopt;

    size_t offset = 0;
    auto read_u8  = [&]() -> uint8_t  { return bytes[offset++]; };
    auto read_u16 = [&]() -> uint16_t {
        uint16_t v; std::memcpy(&v, bytes + offset, 2); offset += 2;
        return ntohs(v);
    };
    auto read_u32 = [&]() -> uint32_t {
        uint32_t v; std::memcpy(&v, bytes + offset, 4); offset += 4;
        return ntohl(v);
    };
    auto read_u64 = [&]() -> uint64_t {
        uint64_t v; std::memcpy(&v, bytes + offset, 8); offset += 8;
        return safelink_ntohll(v);
    };

    PacketHeader h;
    h.magic           = read_u32();
    h.version         = read_u8();
    h.frame_type      = read_u8();
    h.flags           = read_u16();
    h.sequence_number = read_u32();
    h.session_id      = read_u64();
    h.payload_length  = read_u32();
    h.header_checksum = read_u8();

    // --- Validation ---

    if (h.magic != SAFELINK_MAGIC) {
        LOG_WARNING("ProtocolHandler",
            "Bad magic: 0x" << std::hex << h.magic << " (expected 0x"
            << SAFELINK_MAGIC << ")");
        return std::nullopt;
    }

    if (h.version != SAFELINK_PROTOCOL_VERSION) {
        LOG_WARNING("ProtocolHandler",
            "Unsupported protocol version: " << static_cast<int>(h.version));
        return std::nullopt;
    }

    if (h.payload_length > SAFELINK_MAX_PAYLOAD) {
        LOG_WARNING("ProtocolHandler",
            "payload_length " << h.payload_length
            << " exceeds SAFELINK_MAX_PAYLOAD " << SAFELINK_MAX_PAYLOAD);
        return std::nullopt;
    }

    // Verify header checksum: recompute over bytes [0, HEADER_SIZE-2)
    // i.e., all fields except the checksum byte itself.
    uint8_t expected_cs = compute_header_checksum(bytes, SAFELINK_HEADER_SIZE - 1);
    if (h.header_checksum != expected_cs) {
        LOG_WARNING("ProtocolHandler",
            "Header checksum mismatch: got 0x" << std::hex
            << static_cast<int>(h.header_checksum)
            << " expected 0x" << static_cast<int>(expected_cs));
        return std::nullopt;
    }

    return h;
}

// =============================================================================
// build_packet()
// =============================================================================

std::vector<uint8_t> ProtocolHandler::build_packet(
    FrameType                   frame_type,
    uint64_t                    session_id,
    uint32_t                    seq,
    uint16_t                    flags,
    const std::vector<uint8_t>& payload)
{
    // Enforce payload size limit before allocating.
    if (payload.size() > SAFELINK_MAX_PAYLOAD) {
        throw std::runtime_error(
            "ProtocolHandler::build_packet: payload exceeds SAFELINK_MAX_PAYLOAD");
    }

    PacketHeader hdr;
    hdr.magic           = SAFELINK_MAGIC;
    hdr.version         = SAFELINK_PROTOCOL_VERSION;
    hdr.frame_type      = static_cast<uint8_t>(frame_type);
    hdr.flags           = flags;
    hdr.sequence_number = seq;
    hdr.session_id      = session_id;
    hdr.payload_length  = static_cast<uint32_t>(payload.size());
    hdr.header_checksum = 0; // computed inside serialise_header()

    auto header_bytes = serialise_header(hdr);

    // Concatenate header + payload into a single contiguous buffer.
    std::vector<uint8_t> packet;
    packet.reserve(SAFELINK_HEADER_SIZE + payload.size());
    packet.insert(packet.end(), header_bytes.begin(), header_bytes.end());
    packet.insert(packet.end(), payload.begin(), payload.end());

    LOG_TRACE("ProtocolHandler",
        "Built packet: type=" << frame_type_to_string(frame_type)
        << " seq=" << seq
        << " payload=" << payload.size() << "B"
        << " total=" << packet.size() << "B");

    return packet;
}

// =============================================================================
// parse_packet()
// =============================================================================

std::optional<ProtocolHandler::ParseResult>
ProtocolHandler::parse_packet(const std::vector<uint8_t>& buffer)
{
    if (buffer.size() < SAFELINK_HEADER_SIZE) {
        LOG_WARNING("ProtocolHandler",
            "Buffer too small to hold a header: " << buffer.size() << " bytes");
        return std::nullopt;
    }

    auto maybe_header = deserialise_header(buffer.data());
    if (!maybe_header) {
        return std::nullopt; // Error already logged in deserialise_header
    }

    const PacketHeader& hdr = *maybe_header;
    const size_t expected_total = SAFELINK_HEADER_SIZE + hdr.payload_length;

    if (buffer.size() != expected_total) {
        LOG_WARNING("ProtocolHandler",
            "Buffer length " << buffer.size()
            << " != expected " << expected_total
            << " (header says payload_length=" << hdr.payload_length << ")");
        return std::nullopt;
    }

    ParseResult result;
    result.header = hdr;

    if (hdr.payload_length > 0) {
        result.payload.assign(
            buffer.begin() + static_cast<ptrdiff_t>(SAFELINK_HEADER_SIZE),
            buffer.end());
    }

    LOG_TRACE("ProtocolHandler",
        "Parsed packet: type=" << frame_type_to_string(static_cast<FrameType>(hdr.frame_type))
        << " seq=" << hdr.sequence_number
        << " payload=" << hdr.payload_length << "B");

    return result;
}

// =============================================================================
// compute_header_checksum()
// =============================================================================

uint8_t ProtocolHandler::compute_header_checksum(const uint8_t* data, size_t length)
{
    uint8_t checksum = 0;
    for (size_t i = 0; i < length; ++i) {
        checksum ^= data[i];
    }
    return checksum;
}

// =============================================================================
// frame_type_to_string()
// =============================================================================

const char* ProtocolHandler::frame_type_to_string(FrameType ft) {
    switch (ft) {
        case FrameType::DISCOVERY_PING:     return "DISCOVERY_PING";
        case FrameType::DISCOVERY_PONG:     return "DISCOVERY_PONG";
        case FrameType::KEY_EXCHANGE_INIT:  return "KEY_EXCHANGE_INIT";
        case FrameType::KEY_EXCHANGE_REPLY: return "KEY_EXCHANGE_REPLY";
        case FrameType::KEY_EXCHANGE_COMMIT:return "KEY_EXCHANGE_COMMIT";
        case FrameType::SESSION_READY:      return "SESSION_READY";
        case FrameType::SECURE_MESSAGE:     return "SECURE_MESSAGE";
        case FrameType::FILE_TRANSFER_INIT: return "FILE_TRANSFER_INIT";
        case FrameType::FILE_CHUNK:         return "FILE_CHUNK";
        case FrameType::FILE_TRANSFER_END:  return "FILE_TRANSFER_END";
        case FrameType::FILE_ACK:           return "FILE_ACK";
        case FrameType::SESSION_CLOSE:      return "SESSION_CLOSE";
        case FrameType::HEARTBEAT_PING:     return "HEARTBEAT_PING";
        case FrameType::HEARTBEAT_PONG:     return "HEARTBEAT_PONG";
        case FrameType::PROTOCOL_ERROR:     return "PROTOCOL_ERROR";
        default:                            return "UNKNOWN";
    }
}

// =============================================================================
// generate_session_id()
// =============================================================================

uint64_t ProtocolHandler::generate_session_id() {
    uint64_t id = 0;
    if (RAND_bytes(reinterpret_cast<uint8_t*>(&id), sizeof(id)) != 1) {
        LOG_FATAL("ProtocolHandler",
            "RAND_bytes failed — OpenSSL PRNG not seeded. Aborting.");
        throw std::runtime_error("RAND_bytes failed in generate_session_id()");
    }
    return id;
}

// =============================================================================
// Payload Serialisation Helpers
// =============================================================================

std::vector<uint8_t> ProtocolHandler::serialise(const DiscoveryPayload& p) {
    std::vector<uint8_t> buf;
    buf.reserve(sizeof(p.node_name) + 2 + sizeof(p.ipv4_address) + 8);

    auto append = [&](const void* src, size_t n) {
        const auto* s = static_cast<const uint8_t*>(src);
        buf.insert(buf.end(), s, s + n);
    };

    append(p.node_name.data(),    p.node_name.size());
    uint16_t port_net = htons(p.tcp_port);
    append(&port_net, 2);
    append(p.ipv4_address.data(), p.ipv4_address.size());
    uint64_t ts_net = safelink_htonll(p.timestamp);
    append(&ts_net, 8);

    return buf;
}

std::optional<DiscoveryPayload>
ProtocolHandler::deserialise_discovery(const std::vector<uint8_t>& bytes) {
    constexpr size_t MIN_SIZE = 64 + 2 + 16 + 8; // = 90 bytes
    if (bytes.size() < MIN_SIZE) return std::nullopt;

    DiscoveryPayload p;
    size_t off = 0;
    std::memcpy(p.node_name.data(),    bytes.data() + off, 64); off += 64;
    uint16_t port_net; std::memcpy(&port_net, bytes.data() + off, 2); off += 2;
    p.tcp_port = ntohs(port_net);
    std::memcpy(p.ipv4_address.data(), bytes.data() + off, 16); off += 16;
    uint64_t ts_net; std::memcpy(&ts_net, bytes.data() + off, 8);
    p.timestamp = safelink_ntohll(ts_net);
    return p;
}

std::vector<uint8_t> ProtocolHandler::serialise(const MessageBody& body) {
    std::vector<uint8_t> buf;
    uint64_t ts_net = safelink_htonll(body.timestamp_ms);
    const auto* ts_ptr = reinterpret_cast<const uint8_t*>(&ts_net);
    buf.insert(buf.end(), ts_ptr, ts_ptr + 8);
    buf.insert(buf.end(), body.text.begin(), body.text.end());
    return buf;
}

std::optional<MessageBody>
ProtocolHandler::deserialise_message(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 8) return std::nullopt;
    MessageBody body;
    uint64_t ts_net; std::memcpy(&ts_net, bytes.data(), 8);
    body.timestamp_ms = safelink_ntohll(ts_net);
    body.text.assign(
        reinterpret_cast<const char*>(bytes.data() + 8),
        bytes.size() - 8);
    return body;
}

std::vector<uint8_t> ProtocolHandler::serialise(const FileMetaBody& b) {
    std::vector<uint8_t> buf;
    auto append = [&](const void* src, size_t n) {
        const auto* s = static_cast<const uint8_t*>(src);
        buf.insert(buf.end(), s, s + n);
    };
    append(b.filename.data(), b.filename.size());
    uint64_t tb_net  = safelink_htonll(b.total_bytes);   append(&tb_net,  8);
    append(b.sha256_digest.data(), b.sha256_digest.size());
    uint32_t tc_net  = htonl(b.total_chunks);            append(&tc_net,  4);
    uint32_t cs_net  = htonl(b.chunk_size);              append(&cs_net,  4);
    uint64_t tid_net = safelink_htonll(b.transfer_id);   append(&tid_net, 8);
    return buf;
}

std::vector<uint8_t> ProtocolHandler::serialise(const FileChunkBody& b) {
    std::vector<uint8_t> buf;
    auto append = [&](const void* src, size_t n) {
        const auto* s = static_cast<const uint8_t*>(src);
        buf.insert(buf.end(), s, s + n);
    };
    uint64_t tid_net = safelink_htonll(b.transfer_id);  append(&tid_net, 8);
    uint32_t ci_net  = htonl(b.chunk_index);            append(&ci_net,  4);
    uint32_t dl_net  = htonl(b.data_length);            append(&dl_net,  4);
    uint8_t  lc      = b.last_chunk ? 1 : 0;            append(&lc,      1);
    append(b.data.data(), b.data.size());
    return buf;
}

} // namespace SafeLink
