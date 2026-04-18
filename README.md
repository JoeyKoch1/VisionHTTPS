# Vision HTTPS

A from-scratch HTTPS/1.1 server written in C, C++, and x86-64 Assembly.
**Zero external dependencies. Zero libc linkage. Zero externs.**

---

## Architecture

| Layer | File(s) | Description |
|---|---|---|
| Syscall / ASM | `platform/*/syscall.asm` | Raw OS syscall stubs |
| Memory | `src/mem/arena.c`, `slab.c` | Arena + slab allocators |
| Network I/O | `src/net/event_loop.c` | epoll / kqueue / IOCP |
| Crypto | `src/crypto/` | SHA-256, AES-GCM, ChaCha20-Poly1305, X25519, HMAC, HKDF |
| TLS 1.3 | `src/tls/` | Full handshake state machine + record layer |
| HTTP/1.1 | `src/http/` | Zero-copy parser + response builder |
| Router | `src/router/` | Trie-based router + middleware chain |
| Config | `src/config.c` | Config file parser + PEM decoder |

---

## Build — Linux (GCC/Clang + NASM)

```bash
# Prerequisites: cmake >= 3.22, gcc or clang, nasm
sudo apt install cmake nasm build-essential

mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Run tests
./bin/vision_tests

# Start server
./bin/vision_server
```

---

## Build — macOS (Clang + NASM)

```bash
# Prerequisites: Xcode CLT, cmake, nasm
brew install cmake nasm

mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(sysctl -n hw.ncpu)

./bin/vision_tests
./bin/vision_server
```

---

## Build — Windows (MSVC + MASM)

```powershell
# Prerequisites: Visual Studio 2022 (with C++ workload), CMake

mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release

.\bin\Release\vision_tests.exe
.\bin\Release\vision_server.exe
```

---

## Configuration

Edit `vision.conf` (loaded from the working directory):

```ini
port      = 8443
cert      = /path/to/cert.pem
key       = /path/to/key.pem
backlog   = 128
max_conns = 4096
```

---

## TLS certificate (self-signed for dev)

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=localhost"
```

---

## Cipher suites supported

| Suite | RFC | Notes |
|---|---|---|
| `TLS_AES_128_GCM_SHA256` | RFC 8446 | AES-NI accelerated on x86-64 |
| `TLS_CHACHA20_POLY1305_SHA256` | RFC 8446 | Preferred on ARM64 |

Key exchange: **X25519** (RFC 7748) only.

---

## Crypto primitives

All implemented from scratch, no OpenSSL, no mbedTLS:

- **SHA-256** — FIPS 180-4 (NIST test vectors pass)
- **AES-128/256-GCM** — AES-NI + CLMUL GHASH on x86-64
- **ChaCha20-Poly1305** — RFC 8439 (RFC test vectors pass)
- **X25519** — RFC 7748, Montgomery ladder, constant-time (RFC test vectors pass)
- **HMAC-SHA-256** — RFC 2104
- **HKDF** — RFC 5869 (RFC test vectors pass)

---

## Sprint roadmap

| Sprint | Status | Deliverable |
|---|---|---|
| 1 | ✅ Done | Syscalls, allocators, SHA-256, ChaCha20, AES-GCM |
| 2 | ✅ Done | X25519, TLS 1.3 handshake, record layer, HTTP parser, router |
| 3 | 🔜 Next | Full AEAD record encryption, client Finished verify, kqueue/IOCP |
| 4 | 🔜 | HTTP/2 + HPACK, 0-RTT session resumption |
| 5 | 🔜 | ARM64 NEON/AES-CE acceleration, Windows NT direct syscalls |
