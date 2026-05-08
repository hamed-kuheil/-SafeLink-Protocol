# 🛡️ SafeLink Protocol

> **Secure Peer-to-Peer LAN Communication System**  
> A modular C++ networking project implementing encrypted messaging and file transfer over local area networks using hybrid RSA/AES-GCM cryptography.

---

# 📖 Overview

SafeLink Protocol is a peer-to-peer (P2P) LAN communication framework designed to provide secure and efficient messaging and file transfer without relying on centralized servers.

The project focuses on:

- Secure session establishment
- Authenticated encryption
- Reliable packet framing
- Modular layered architecture
- High-performance asynchronous networking

The system is implemented in modern C++ using a clean engineering-oriented design suitable for academic and low-level systems programming environments.

---

# ✨ Core Features

- 🔍 UDP multicast peer discovery
- 🔐 RSA-2048 + AES-256-GCM hybrid encryption
- 📦 Custom binary packet framing protocol
- 📁 Encrypted file transfer support
- 🧵 Thread-safe asynchronous logger
- ⚡ Boost.Asio asynchronous networking
- 🛡️ Replay protection using session IDs and sequence counters
- ✅ Packet integrity and validation checks
- 🧱 Modular layered architecture

---

# 🏗️ Architecture Overview

```ascii
┌─────────────────────────────────────────────────────────────────┐
│                         CLI / UI Layer                          │
│                           main.cpp                              │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                      Protocol / Framing Layer                   │
│                       ProtocolHandler                           │
│                                                                 │
│  • Packet serialisation / deserialisation                       │
│  • Frame type discrimination                                    │
│  • Wire-format validation                                       │
│  • Header checksum verification                                 │
└───────────────┬──────────────────────────────┬──────────────────┘
                │                              │
┌───────────────▼──────────────┐ ┌─────────────▼────────────────┐
│       Security Layer         │ │       Network Layer           │
│      SecurityManager         │ │      NetworkManager           │
│                               │ │                               │
│  • RSA-2048 key generation   │ │  • TCP session management     │
│  • RSA-OAEP key exchange     │ │  • UDP multicast discovery    │
│  • AES-256-GCM encryption    │ │  • Async I/O (Boost.Asio)     │
│  • SHA-256 hashing           │ │  • Connection handling        │
└──────────────────────────────┘ └──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                         Logger Layer                            │
│                                                                 │
│  • Thread-safe logging                                          │
│  • Async queue processing                                       │
│  • Log-level filtering                                          │
│  • Meyers Singleton pattern                                     │
└─────────────────────────────────────────────────────────────────┘
```

---

# 📡 Wire Format

Each transmitted packet follows a fixed binary structure:

```ascii
┌───────────────────────────────────────────────────────────┐
│  PacketHeader  (25 bytes, network byte order)            │
├───────────────────────────────────────────────────────────┤
│  magic           uint32  0x534C504B ("SLPK")             │
│  version         uint8   Protocol version                │
│  frame_type      uint8   FrameType enum                  │
│  flags           uint16  PacketFlags bitmask             │
│  sequence_number uint32  Session sequence counter        │
│  session_id      uint64  Random session identifier       │
│  payload_length  uint32  Payload size in bytes           │
│  header_checksum uint8   XOR checksum                    │
├───────────────────────────────────────────────────────────┤
│  Payload (variable length, optional AES-GCM encrypted)   │
└───────────────────────────────────────────────────────────┘
```

---

# 🔒 Security Design

| Security Concern | Mechanism |
|---|---|
| Key Exchange | RSA-2048 with OAEP/SHA-256 |
| Payload Encryption | AES-256-GCM |
| Nonce/IV Generation | 96-bit random IV via `RAND_bytes()` |
| Authentication | GCM authentication tag |
| Additional Authenticated Data | Serialised packet header |
| File Integrity | SHA-256 hashing |
| Replay Prevention | Session IDs + monotonic sequence counters |

---

# 🧱 Project Structure

```text
SafeLink_Protocol/
├── CMakeLists.txt
├── README.md
├── include/
│   ├── ProtocolHandler.hpp
│   ├── SecurityManager.hpp
│   ├── NetworkManager.hpp
│   └── Logger.hpp
│
├── src/
│   ├── main.cpp
│   ├── ProtocolHandler.cpp
│   ├── SecurityManager.cpp
│   ├── NetworkManager.cpp
│   └── Logger.cpp
│
└── tests/
    └── test_security.cpp
```

---

# 🛠️ Build Instructions

## Prerequisites

| Dependency | Required Version |
|---|---|
| CMake | 3.20+ |
| GCC | 7+ |
| Clang | 5+ |
| OpenSSL | 1.1+ |
| Boost | 1.74+ (optional) |

---

## Build

```bash
mkdir build && cd build

cmake .. -DCMAKE_BUILD_TYPE=Release

cmake --build . --parallel
```

---

## Run

```bash
./safelink
```

---

## Test

```bash
ctest --output-on-failure

# or directly

./test_security
```

---

# 🗺️ Development Roadmap

| Iteration | Deliverable | Status |
|---|---|---|
| Iteration 1 | ProtocolHandler + Logger + Build System | ✅ Complete |
| Iteration 2 | SecurityManager (RSA/AES-GCM) | ⏳ In Progress |
| Iteration 3 | NetworkManager (TCP/UDP) | ⏳ Pending |
| Iteration 4 | CLI Integration | ⏳ Pending |
| Iteration 5 | Performance Optimisation & Testing | ⏳ Pending |

---

# 🎯 Engineering Goals

The project is intended to explore and demonstrate:

- Low-level network programming
- Secure protocol design
- Binary serialisation
- Modern C++ architecture
- Applied cryptography
- Concurrent systems programming

---

# 👨‍💻 Developer

**Hamed Kuheil**  
Computer Engineering & Software Engineering Student

### Areas of Interest

- Systems Programming
- Cybersecurity
- Secure Network Architecture
- Backend Engineering
- Applied Cryptography

---

# 📜 License

Licensed under the MIT License.

This project is intended for educational and research purposes.
