Tested on iOS 5.1 with wikipedia.org, which uses TLS 1.3.

Built using a modified version of Theos and the stock iOS 5.1 SDK.

The `.deb` file is located in the `packages` directory.

## Build Instructions

```bash
rm -f certs_bundle.h
make clean
make package FINALPACKAGE=1 SIGN=0
```

# Overview

---

# PROJECT SUMMARY: REVERSE-PORTING TLS 1.3 TO iOS 5.1

---

## 1. Architectural Overview

The **TLS13Browser** application injects a modern, self-contained network layer into an obsolete operating system (iOS 5.1, Manual Reference Counting). It intercepts global UIKit web requests to bypass Apple's outdated Secure Transport framework.

```text
[ UIWebView ]
      │ (Triggers HTTPS Request)
      ▼
[ NSURLProtocol (TLS13URLProtocol) ] <--> Intercepts 'https://' requests
      │
      ▼
[ mbedTLS 3.x Engine Core ] ───────> [ Raw POSIX Sockets ] ───────> [ Target Server ]
   - PSA Crypto Subsystem
   - Static Root CA Array
   - State-Machine Parser
   - ALPN Compliance (http/1.1)
```

## 2. Core Engineering Milestones & Fixes

### Network Interception

Subclassed `NSURLProtocol` to trap outbound HTTPS calls. Spawns background dispatch queues to handle execution blocks without blocking the main WebKit thread.

### Embedded Crypto Engine

Static linking of `mbedTLS 3.x` with the required `PSA Crypto` abstraction layer to compute modern cryptographic primitives natively unavailable on iOS 5.

### Post-Handshake Handling

Resolved a critical read-loop termination crash. TLS 1.3 servers issue post-handshake `NewSessionTicket` messages immediately following connection setup.

Catching the specific mbedTLS return status:

```c
MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET
```

(`-0x7B00`) allows the app to process the ticket and continue reading data streams safely.

### Extension Compliance

Injected Application-Layer Protocol Negotiation (ALPN) tokens (`"http/1.1"`) directly into the client handshake profile. This satisfies strict validation on modern edge firewalls that reject unnegotiated TLS 1.3 clients.

### HTTP/1.1 State Parser

Built a custom HTTP text engine that processes both `\r\n` and `\n` line boundaries. It:

- Separates headers from payload bytes
- Detects redirect responses (`301`/`302`)
- Triggers follow-up requests automatically
- Forces uncompressed responses via:

```http
Accept-Encoding: identity
```

## 3. Repository Blueprint

| File | Description |
|--------|-------------|
| `TLS13AppDelegate.m` | Bootstraps the application window and allocates screen space for a live on-device log terminal. |
| `TLS13URLProtocol.m` | Proxies WebKit requests, drives low-level mbedTLS socket operations, parses uncompressed HTTP traffic, and delivers clean payloads. |
| `certs_bundle.h` | Contains modern root certificate bundles compiled into the application to replace the device's expired trust store. |

---

**Result:** A self-contained TLS 1.3 networking stack capable of establishing secure connections from an unmodified iOS 5.1 environment using modern certificate chains and cryptographic standards.
