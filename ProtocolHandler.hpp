// =============================================================================
// SafeLink Protocol — include/ProtocolHandler.hpp
// =============================================================================
//
// PURPOSE:
//   This header defines the entire wire-format contract of the SafeLink
//   Protocol. Every byte that travels over the network is described here.
//
// DESIGN RATIONALE — "Why a separate Protocol Layer?":
//   The Protocol Layer sits between the Network Layer (raw bytes in/out) and
//   the Security Layer (encrypt/decrypt). This strict separation means:
//     1. NetworkManager knows NOTHING about crypto.
//     2. SecurityManager knows NOTHING about sockets.
//     3. ProtocolHandler knows NOTHING about either — it only frames data.
//   This makes each layer independently unit-testable and replaceable.
//
// WIRE FORMAT OVERVIEW:
//   Every packet has a fixed-size PacketHeader followed by a variable-length
//   payload whose interpretation depends on the FrameType field.
//
//   ┌────────────────────────────────────────────────────────┐
//   │  PacketHeader  (SAFELINK_HEADER_SIZE bytes, fixed)     │
//   ├────────────────────────────────────────────────────────┤
//   │  Payload  (header.payload_length bytes, variable)      │
//   └────────────────────────────────────────────────────────┘
//
// ENDIANNESS:
//   All multi-byte integer fields are stored in NETWORK byte order (big-endian)
//   using htonl/ntohl. This is the IETF convention and ensures interoperability
//   between x86 (little-endian) and ARM/MIPS (often big-endian) peers.
//
// =============================================================================

#pragma once  // WHY #pragma once over include guards?
              // #pragma once is supported by every major compiler (GCC, Clang,
              // MSVC) and avoids the double-inclusion bug that arises when
              // someone copies a guard macro verbatim. It is also marginally
              // faster because the compiler can skip the file entirely after
              // the first inclusion.

#include <array>        // std::array — fixed-size stack-allocated buffers
#include <cstdint>      // uint8_t, uint16_t, uint32_t, uint64_t — exact widths
#include <cstring>      // std::memcpy, std::memset
#include <optional>     // std::optional — nullable return values without pointers
#include <span>         // std::span (C++20) — non-owning view over contiguous data
#include <string>       // std::string
#include <vector>       // std::vector — heap-allocated dynamic buffers

// WHY include <cstdint> explicitly?
// sizeof(int) is implementation-defined (2, 4, or 8 bytes depending on
// platform/ABI). Network protocols MUST use fixed-width integer types to
// guarantee a stable wire format across heterogeneous nodes.

namespace SafeLink {

// =============================================================================
// SECTION 1: Protocol Constants
// =============================================================================

/// Magic bytes prefixed to every packet header.
/// WHY a magic number? It acts as a sanity check when reading from a stream.
/// If the first four bytes are not SAFELINK_MAGIC, the data is corrupt or
/// belongs to a different protocol entirely — we discard it immediately.
/// The value 0x534C504B spells "SLPK" (SafeLink PacKet) in ASCII.
constexpr uint32_t SAFELINK_MAGIC = 0x534C504B;

/// Protocol version encoded in the header.
/// WHY version the protocol? Future breaking changes (new frame types,
/// changed field widths) can be detected and rejected gracefully rather
/// than silently corrupting data.
constexpr uint8_t SAFELINK_PROTOCOL_VERSION = 1;

/// Maximum permitted payload size (4 MiB).
/// WHY a cap? Without one, a malicious peer can send a header claiming
/// payload_length = UINT32_MAX and exhaust the receiver's heap — a classic
/// "death by allocation" DoS. 4 MiB is generous for messages; file chunks
/// use their own chunking logic.
constexpr uint32_t SAFELINK_MAX_PAYLOAD = 4 * 1024 * 1024; // 4 MiB

/// AES-GCM IV (nonce) length in bytes.
/// WHY 12 bytes? NIST SP 800-38D recommends a 96-bit (12-byte) IV for
/// AES-GCM when using the standard construction, because it avoids the
/// costly GHASH computation needed for non-96-bit IVs and gives the full
/// 128-bit authentication tag strength.
constexpr size_t AES_GCM_IV_LENGTH = 12;

/// AES-GCM authentication tag length in bytes.
/// A 16-byte (128-bit) tag provides the maximum forgery resistance (~2^-128
/// per attempt). Never truncate GCM tags in a security-critical application.
constexpr size_t AES_GCM_TAG_LENGTH = 16;

/// RSA key size in bits used for key exchange.
/// WHY 2048? It meets NIST recommendation through 2030. 4096-bit would be
/// stronger but the RSA operation is ~8x slower and the larger key blows
/// up the KEY_EXCHANGE packet; 2048 is the production sweet spot for a
/// LAN application.
constexpr int RSA_KEY_BITS = 2048;

/// SHA-256 digest length in bytes.
constexpr size_t SHA256_DIGEST_LENGTH = 32;

/// Discovery multicast group address (IPv4).
/// WHY multicast? Unlike broadcast, multicast is routable and does not
/// flood every host on the subnet — only hosts that have joined the group
/// receive DISCOVERY_PING frames.
constexpr const char* SAFELINK_MULTICAST_GROUP = "239.255.42.99";

/// Well-known UDP port for discovery frames.
constexpr uint16_t SAFELINK_DISCOVERY_PORT = 54321;

/// Well-known TCP port for encrypted sessions.
constexpr uint16_t SAFELINK_SESSION_PORT    = 54322;


// =============================================================================
// SECTION 2: Frame Type Enumeration
// =============================================================================
//
// WHY enum class over plain enum?
//   1. SCOPED: FrameType::DISCOVERY_PING, not just DISCOVERY_PING.
//      Prevents accidental clashes with identically-named macros or enums.
//   2. STRONGLY TYPED: You cannot implicitly convert a FrameType to an int
//      or mix it with an unrelated enum, eliminating an entire class of bugs.
//   3. uint8_t UNDERLYING TYPE: Guarantees the value fits in one byte on the
//      wire without any platform-specific behaviour.
//
enum class FrameType : uint8_t {
    // -------------------------------------------------------------------------
    // Discovery Phase (sent over UDP, unencrypted)
    // -------------------------------------------------------------------------

    /// Broadcast/multicast ping to announce presence on the LAN.
    /// Payload: DiscoveryPayload (peer name, listening TCP port).
    DISCOVERY_PING  = 0x01,

    /// Reply from a peer acknowledging a DISCOVERY_PING.
    /// Payload: DiscoveryPayload (peer name, listening TCP port).
    DISCOVERY_PONG  = 0x02,

    // -------------------------------------------------------------------------
    // Handshake Phase (sent over TCP, partially unencrypted)
    // -------------------------------------------------------------------------

    /// Step 1 of the key-exchange handshake: initiating peer sends its
    /// RSA-2048 public key (DER-encoded) to the responder.
    /// Payload: KeyExchangePayload (DER bytes of the public key).
    KEY_EXCHANGE_INIT   = 0x10,

    /// Step 2 of the key-exchange: responder replies with its own RSA public
    /// key. Both sides now hold each other's public keys.
    /// Payload: KeyExchangePayload.
    KEY_EXCHANGE_REPLY  = 0x11,

    /// Step 3: initiating peer generates a random 256-bit AES session key,
    /// encrypts it with the responder's RSA public key (OAEP/SHA-256 padding),
    /// and sends the ciphertext.
    /// Payload: EncryptedKeyPayload (RSA-encrypted AES key blob).
    KEY_EXCHANGE_COMMIT = 0x12,

    /// Final handshake step: responder sends a small known-plaintext
    /// "READY" token encrypted with the negotiated AES-GCM session key.
    /// The initiator verifies this to confirm the session key was received
    /// and decrypted correctly — mutual key confirmation without a full
    /// PKI certificate chain.
    /// Payload: SecurePayload (AES-GCM encrypted "READY" token).
    SESSION_READY       = 0x13,

    // -------------------------------------------------------------------------
    // Session Phase (all frames AES-GCM encrypted after SESSION_READY)
    // -------------------------------------------------------------------------

    /// UTF-8 text message between peers.
    /// Payload: SecurePayload wrapping a MessageBody.
    SECURE_MESSAGE  = 0x20,

    /// First frame of a multi-chunk file transfer, carries metadata.
    /// Payload: SecurePayload wrapping a FileMetaBody.
    FILE_TRANSFER_INIT  = 0x30,

    /// Intermediate data chunk in a file transfer.
    /// Payload: SecurePayload wrapping a FileChunkBody.
    FILE_CHUNK      = 0x31,

    /// Final frame of a file transfer; receiver should assemble and verify.
    /// Payload: SecurePayload wrapping a FileChunkBody (last_chunk = true)
    ///          followed by a SHA-256 digest of the complete file.
    FILE_TRANSFER_END   = 0x32,

    /// Sender-side acknowledgement / NAK for a file chunk.
    /// Payload: FileAckBody (chunk_index, status).
    FILE_ACK        = 0x33,

    // -------------------------------------------------------------------------
    // Control Frames
    // -------------------------------------------------------------------------

    /// Graceful session termination request.
    /// Payload: empty (payload_length = 0).
    SESSION_CLOSE   = 0x40,

    /// Heartbeat / keep-alive. Sent every N seconds to detect dead peers.
    /// Payload: PingPayload (timestamp).
    HEARTBEAT_PING  = 0x41,

    /// Response to a HEARTBEAT_PING.
    /// Payload: PingPayload (echoed timestamp for RTT calculation).
    HEARTBEAT_PONG  = 0x42,

    /// Error notification. Sent when a peer encounters a non-fatal protocol
    /// violation and wants to inform the other side before closing.
    /// Payload: ErrorPayload (error code, human-readable description).
    PROTOCOL_ERROR  = 0xFF,
};

// =============================================================================
// SECTION 3: Packet Header
// =============================================================================
//
// WHY #pragma pack(push, 1) / #pragma pack(pop)?
//   By default, the compiler inserts padding between struct members to satisfy
//   alignment requirements. A PacketHeader laid out at a natural alignment
//   might be 24 bytes on one compiler and 28 on another. We MUST disable
//   padding so that sizeof(PacketHeader) is EXACTLY the sum of its fields —
//   both for the sender writing into a send buffer and the receiver casting
//   a receive buffer back to a PacketHeader.
//
// WHY NOT use __attribute__((packed)) (GCC/Clang extension)?
//   #pragma pack is also an extension, but it is supported by MSVC, GCC,
//   and Clang identically. We use it here for maximum portability.
//   An alternative is to manually serialise/deserialise each field, which
//   avoids the extension entirely — see ProtocolHandler::serialise_header().
//
#pragma pack(push, 1)

struct PacketHeader {
    uint32_t magic;           ///< Must equal SAFELINK_MAGIC (0x534C504B).
                              ///  In network byte order (big-endian).

    uint8_t  version;         ///< Protocol version. Currently SAFELINK_PROTOCOL_VERSION (1).

    uint8_t  frame_type;      ///< Discriminator — cast to FrameType before use.
                              ///  Kept as uint8_t in the header for wire portability.

    uint16_t flags;           ///< Bitfield of option flags (see PacketFlags below).
                              ///  Network byte order.

    uint32_t sequence_number; ///< Monotonically-increasing per-session counter.
                              ///  WHY? Allows the receiver to detect dropped or
                              ///  replayed packets. A replayed packet will have
                              ///  a sequence number the receiver has already seen.
                              ///  Network byte order.

    uint64_t session_id;      ///< Random 64-bit identifier assigned at session
                              ///  establishment. Prevents cross-session packet
                              ///  injection. Network byte order.

    uint32_t payload_length;  ///< Byte length of the payload following this header.
                              ///  MUST be <= SAFELINK_MAX_PAYLOAD. Network byte order.

    uint8_t  header_checksum; ///< Simple XOR checksum of bytes [0..sizeof-2].
                              ///  WHY XOR and not CRC-32? The header itself is
                              ///  tiny (≤20 bytes) and we only need corruption
                              ///  detection, not correction. XOR is O(n) with
                              ///  near-zero CPU overhead, which matters in a
                              ///  high-frequency heartbeat path.
                              ///  The full payload is protected by AES-GCM's
                              ///  128-bit authentication tag — a far stronger
                              ///  integrity guarantee.
};

#pragma pack(pop)

/// Compile-time check: the header must be exactly 20 bytes on the wire.
/// If this assertion fires, a padding byte crept in — investigate alignment.
static_assert(sizeof(PacketHeader) == 20,
    "PacketHeader size mismatch — check pragma pack or field widths.");

/// Symbolic constant so the rest of the codebase never hard-codes 20.
constexpr size_t SAFELINK_HEADER_SIZE = sizeof(PacketHeader);


// =============================================================================
// SECTION 4: Packet Flags Bitfield
// =============================================================================

/// Flags packed into PacketHeader::flags (16 bits available).
/// Usage: header.flags = htons(static_cast<uint16_t>(PacketFlags::COMPRESSED));
namespace PacketFlags {
    constexpr uint16_t NONE        = 0x0000;
    constexpr uint16_t COMPRESSED  = 0x0001; ///< Payload is zlib-compressed (future).
    constexpr uint16_t FRAGMENTED  = 0x0002; ///< Packet is one fragment of a larger PDU.
    constexpr uint16_t LAST_FRAG   = 0x0004; ///< This is the last fragment.
    constexpr uint16_t URGENT      = 0x0008; ///< Deliver before queued data (future QoS).
} // namespace PacketFlags


// =============================================================================
// SECTION 5: Payload Body Definitions
// =============================================================================
// Each FrameType has a corresponding payload struct. The SecurityManager
// wraps session-phase payloads in a SecurePayload envelope before handing
// them to the NetworkManager.
//
// Naming convention:  <FramePurpose>Body
// All multi-byte integers: network byte order when serialised.

// ---------------------------------------------------------------------------
// 5a. Discovery Payloads (unencrypted UDP)
// ---------------------------------------------------------------------------

/// Payload for DISCOVERY_PING and DISCOVERY_PONG frames.
/// Contains the minimum information a peer needs to initiate a TCP session.
struct DiscoveryPayload {
    /// Human-readable node alias (e.g., "Alice-Laptop").
    /// WHY fixed-size array? Variable-length fields complicate binary
    /// serialisation. 64 bytes is plenty for a hostname/alias.
    std::array<char, 64> node_name{};

    /// TCP port this peer is listening on for incoming connections.
    uint16_t tcp_port{SAFELINK_SESSION_PORT};

    /// Peer's IPv4 address as a dotted-decimal string (e.g., "192.168.1.42").
    /// WHY store it here? The UDP source address the receiver sees might be
    /// different if the node is behind a NAT. Storing it explicitly lets the
    /// peer decide which address to connect to.
    std::array<char, 16> ipv4_address{};

    /// Timestamp (Unix epoch, seconds) when this ping was sent.
    /// Allows receivers to discard stale discovery frames.
    uint64_t timestamp{0};
};

// ---------------------------------------------------------------------------
// 5b. Key-Exchange Payloads (partially encrypted TCP)
// ---------------------------------------------------------------------------

/// Payload for KEY_EXCHANGE_INIT and KEY_EXCHANGE_REPLY.
/// Carries a DER-encoded RSA-2048 public key (~294 bytes).
struct KeyExchangePayload {
    /// Length of the DER-encoded key blob (bytes).
    uint16_t key_length{0};

    /// DER-encoded SubjectPublicKeyInfo (SPKI) blob.
    /// WHY DER? DER is the canonical binary encoding defined by ASN.1/X.690.
    /// It is unambiguous (unlike PEM which is DER + base64 + headers) and
    /// directly consumable by OpenSSL's d2i_PUBKEY().
    /// Max size: RSA-2048 public key in DER is 294 bytes; 512 is safe headroom.
    std::array<uint8_t, 512> key_der{};
};

/// Payload for KEY_EXCHANGE_COMMIT.
/// The AES session key, RSA-OAEP/SHA-256 encrypted with the responder's key.
struct EncryptedKeyPayload {
    /// Length of the encrypted blob (bytes). For RSA-2048 this is always 256.
    uint16_t ciphertext_length{0};

    /// RSA-OAEP encrypted AES-256 key (256 bytes for RSA-2048).
    std::array<uint8_t, 256> ciphertext{};
};

// ---------------------------------------------------------------------------
// 5c. Secure Payload Envelope (session phase — all session frames)
// ---------------------------------------------------------------------------
//
// WHY a separate SecurePayload struct rather than encrypting in-place?
//   The SecurePayload is the "inner packet". It contains the AES-GCM IV,
//   ciphertext, and authentication tag. The PacketHeader (outer) stays
//   cleartext so the receiver can route the frame to the right handler
//   BEFORE decryption. Only after routing does the SecurityManager decrypt
//   the inner body and return the plaintext BodyType (MessageBody, etc.).

struct SecurePayload {
    /// 96-bit AES-GCM nonce/IV. MUST be unique per (session_key, message).
    /// WHY unique? AES-GCM is an authenticated encryption mode. Reusing an
    /// IV with the same key catastrophically breaks both confidentiality AND
    /// authentication — the attacker can XOR two ciphertexts to cancel the
    /// keystream and recover plaintexts. We use a 96-bit random IV generated
    /// fresh for every frame with RAND_bytes().
    std::array<uint8_t, AES_GCM_IV_LENGTH> iv{};

    /// AES-GCM authentication tag (16 bytes / 128 bits).
    /// Covers BOTH the ciphertext AND the additional authenticated data (AAD).
    /// The AAD we use is the serialised PacketHeader — this binds the
    /// ciphertext to its specific header, preventing header-swapping attacks.
    std::array<uint8_t, AES_GCM_TAG_LENGTH> auth_tag{};

    /// Length of the ciphertext in bytes.
    uint32_t ciphertext_length{0};

    /// The encrypted payload bytes. Heap-allocated because size varies.
    std::vector<uint8_t> ciphertext;
};

// ---------------------------------------------------------------------------
// 5d. Message Body (inside SecurePayload for SECURE_MESSAGE)
// ---------------------------------------------------------------------------

struct MessageBody {
    /// Unix timestamp (milliseconds) when the message was composed.
    uint64_t timestamp_ms{0};

    /// UTF-8 encoded message text. The length is inferred from the
    /// SecurePayload::ciphertext_length after decryption.
    std::string text;
};

// ---------------------------------------------------------------------------
// 5e. File-Transfer Bodies (inside SecurePayload)
// ---------------------------------------------------------------------------

/// Sent in FILE_TRANSFER_INIT — metadata about the file to be transferred.
struct FileMetaBody {
    /// Original filename (UTF-8, no path component — strip it on the sender).
    /// WHY strip the path? Path traversal attacks ("../../etc/passwd") are a
    /// classic vulnerability when a remote peer controls a filename.
    std::array<char, 256> filename{};

    /// Total file size in bytes.
    uint64_t total_bytes{0};

    /// SHA-256 digest of the COMPLETE original file.
    /// Verified by the receiver after reassembly to detect corruption or
    /// tampering (belt-and-suspenders on top of per-chunk GCM tags).
    std::array<uint8_t, SHA256_DIGEST_LENGTH> sha256_digest{};

    /// Total number of chunks the transfer will produce.
    uint32_t total_chunks{0};

    /// Size of each chunk in bytes (except possibly the last one).
    uint32_t chunk_size{0};

    /// Unique transfer identifier (random 64-bit value).
    /// Allows multiplexing multiple concurrent file transfers on one session.
    uint64_t transfer_id{0};
};

/// Sent in FILE_CHUNK and FILE_TRANSFER_END.
struct FileChunkBody {
    uint64_t transfer_id{0};   ///< Must match FileMetaBody::transfer_id.
    uint32_t chunk_index{0};   ///< Zero-based index of this chunk.
    uint32_t data_length{0};   ///< Actual bytes in this chunk (≤ chunk_size).
    bool     last_chunk{false};///< True only in FILE_TRANSFER_END.

    /// The raw chunk bytes.
    std::vector<uint8_t> data;
};

/// Sent in FILE_ACK — acknowledgement from receiver.
struct FileAckBody {
    uint64_t transfer_id{0};
    uint32_t chunk_index{0};

    /// Status codes for the ACK.
    enum class Status : uint8_t {
        OK          = 0x00, ///< Chunk received and verified.
        CHECKSUM_FAIL = 0x01, ///< GCM tag verification failed — resend.
        OUT_OF_ORDER  = 0x02, ///< Unexpected chunk_index.
        STORAGE_ERROR = 0x03, ///< Receiver disk I/O failure.
    } status{Status::OK};
};

// ---------------------------------------------------------------------------
// 5f. Control Bodies
// ---------------------------------------------------------------------------

/// Payload for HEARTBEAT_PING / HEARTBEAT_PONG.
struct PingPayload {
    /// Sender's Unix timestamp in microseconds for RTT measurement.
    uint64_t timestamp_us{0};
};

/// Payload for PROTOCOL_ERROR frames.
struct ErrorPayload {
    /// Numeric error code (application-defined).
    uint16_t error_code{0};

    /// Human-readable error description (ASCII, null-terminated).
    std::array<char, 128> description{};
};


// =============================================================================
// SECTION 6: ProtocolHandler Class Declaration
// =============================================================================
//
// The ProtocolHandler is a STATELESS utility class — all methods are static.
// WHY stateless? Framing and parsing are pure input→output transformations
// with no side effects. Making them static:
//   - Eliminates the need to manage a ProtocolHandler instance.
//   - Allows multiple threads to call these functions concurrently without
//     synchronisation (no shared mutable state).
//   - Signals intent clearly: "this is a function, not an object".

class ProtocolHandler {
public:
    // -------------------------------------------------------------------------
    // Serialisation — convert a header struct into a raw byte buffer
    // -------------------------------------------------------------------------

    /// Serialise a PacketHeader into a 20-byte buffer in network byte order.
    ///
    /// WHY manual serialisation instead of a reinterpret_cast + memcpy?
    ///   Although #pragma pack(1) removes compiler padding, a raw cast still
    ///   risks UB on platforms where unaligned reads are illegal (some ARM).
    ///   Explicit field-by-field serialisation with htonl/htons is 100% safe
    ///   and portable.
    ///
    /// @param  header   Populated PacketHeader (host byte order).
    /// @return 20-byte std::array ready to prepend to a send buffer.
    static std::array<uint8_t, SAFELINK_HEADER_SIZE>
    serialise_header(const PacketHeader& header);

    /// Deserialise 20 raw bytes back into a PacketHeader (host byte order).
    ///
    /// @param  bytes  Pointer to at least SAFELINK_HEADER_SIZE bytes.
    /// @return Populated PacketHeader, or std::nullopt if magic/version/checksum
    ///         validation fails.
    ///
    /// WHY std::optional? The caller must handle the "bad packet" case without
    /// relying on exceptions (which can be disabled in embedded/bare-metal builds).
    /// std::optional<T> makes the failure mode explicit in the type system —
    /// the compiler will warn if the caller ignores the return value when it
    /// is annotated with [[nodiscard]].
    [[nodiscard]]
    static std::optional<PacketHeader>
    deserialise_header(const uint8_t* bytes);

    // -------------------------------------------------------------------------
    // Frame Construction — build a complete serialised packet
    // -------------------------------------------------------------------------

    /// Build a complete wire-format packet (header + payload bytes).
    ///
    /// The caller supplies the plaintext (or already-encrypted) payload.
    /// This function computes the header checksum, converts fields to
    /// network byte order, and returns the concatenated buffer.
    ///
    /// @param  frame_type  FrameType discriminator.
    /// @param  session_id  Current session identifier (0 for discovery frames).
    /// @param  seq         Monotonic sequence counter (caller tracks this).
    /// @param  flags       PacketFlags bitmask (default NONE).
    /// @param  payload     Raw payload bytes (may be empty for control frames).
    /// @return Fully serialised packet ready for socket send().
    [[nodiscard]]
    static std::vector<uint8_t> build_packet(
        FrameType               frame_type,
        uint64_t                session_id,
        uint32_t                seq,
        uint16_t                flags,
        const std::vector<uint8_t>& payload
    );

    // -------------------------------------------------------------------------
    // Frame Parsing — split a raw buffer into header + payload
    // -------------------------------------------------------------------------

    /// Result type returned by parse_packet.
    struct ParseResult {
        PacketHeader         header;   ///< Decoded header (host byte order).
        std::vector<uint8_t> payload;  ///< Payload bytes (may be encrypted).
    };

    /// Parse a raw byte buffer into a header + payload pair.
    ///
    /// Performs full validation:
    ///   1. Buffer length ≥ SAFELINK_HEADER_SIZE
    ///   2. Magic bytes match SAFELINK_MAGIC
    ///   3. Protocol version matches SAFELINK_PROTOCOL_VERSION
    ///   4. Header checksum is correct
    ///   5. payload_length ≤ SAFELINK_MAX_PAYLOAD
    ///   6. Buffer length == SAFELINK_HEADER_SIZE + payload_length
    ///
    /// @param  buffer  Complete packet bytes (header + payload).
    /// @return ParseResult on success, std::nullopt on any validation failure.
    [[nodiscard]]
    static std::optional<ParseResult>
    parse_packet(const std::vector<uint8_t>& buffer);

    // -------------------------------------------------------------------------
    // Utility Helpers
    // -------------------------------------------------------------------------

    /// Compute the 1-byte XOR checksum over bytes [0, length).
    /// Used for the PacketHeader::header_checksum field.
    static uint8_t compute_header_checksum(const uint8_t* data, size_t length);

    /// Convert a FrameType to its human-readable name (for logging).
    static const char* frame_type_to_string(FrameType ft);

    /// Generate a new random 64-bit session ID using OpenSSL RAND_bytes.
    /// WHY OpenSSL RAND_bytes and not std::random_device?
    ///   std::random_device may fall back to a pseudo-random generator on
    ///   some platforms (notably some MinGW builds on Windows). OpenSSL's
    ///   RAND_bytes is seeded from /dev/urandom or the OS CSPRNG and is
    ///   cryptographically secure.
    [[nodiscard]]
    static uint64_t generate_session_id();

    // -------------------------------------------------------------------------
    // Payload Serialisation Helpers
    // (Convert typed body structs → raw bytes for encryption)
    // -------------------------------------------------------------------------

    /// Serialise a DiscoveryPayload to bytes.
    static std::vector<uint8_t> serialise(const DiscoveryPayload& payload);

    /// Deserialise bytes back to DiscoveryPayload.
    [[nodiscard]]
    static std::optional<DiscoveryPayload>
    deserialise_discovery(const std::vector<uint8_t>& bytes);

    /// Serialise a MessageBody to bytes.
    static std::vector<uint8_t> serialise(const MessageBody& body);

    /// Deserialise bytes back to MessageBody.
    [[nodiscard]]
    static std::optional<MessageBody>
    deserialise_message(const std::vector<uint8_t>& bytes);

    /// Serialise a FileMetaBody to bytes.
    static std::vector<uint8_t> serialise(const FileMetaBody& body);

    /// Serialise a FileChunkBody to bytes.
    static std::vector<uint8_t> serialise(const FileChunkBody& body);

    // ProtocolHandler is a pure-static utility class; instantiation is
    // meaningless and should be prevented.
    ProtocolHandler() = delete;
    ~ProtocolHandler() = delete;
    ProtocolHandler(const ProtocolHandler&) = delete;
    ProtocolHandler& operator=(const ProtocolHandler&) = delete;
};

} // namespace SafeLink
