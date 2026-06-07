Tested on iOS 5.1 with wikipedia.org, which uses TLS 1.3.

Built using a modified version of Theos and the stock iOS 5.1 SDK.

==Build instructions==
make package FINALPACKAGE=1 SIGN=0

rm -f certs_bundle.h
make clean
make package FINALPACKAGE=1 SIGN=0


==Overview==
================================================================================
          PROJECT SUMMARY: REVERSE-PORTING TLS 1.3 TO iOS 5.1
================================================================================

1. ARCHITECTURAL OVERVIEW
--------------------------------------------------------------------------------
The "TLS13Browser" application injects a modern, self-contained network layer into 
an obsolete operating system (iOS 5.1, Manual Reference Counting). It intercepts 
global UIKit web requests to bypass Apple's outdated Secure Transport framework.

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

2. CORE ENGINEERING MILESTONES & FIXES
--------------------------------------------------------------------------------
* NETWORK INTERCEPTION: Subclassed `NSURLProtocol` to trap out-bound HTTPS calls. 
  Spawns background dispatch queues to handle execution blocks without blocking 
  the main WebKit thread.

* EMBEDDED CRYPTO ENGINE: Static linking of `mbedTLS 3.x` with the required `PSA 
  Crypto` abstraction layer to compute modern cryptographic primitives natively 
  unavailable on iOS 5.

* POST-HANDSHAKE HANDLING: Resolved a critical read-loop termination crash. 
  TLS 1.3 servers issue post-handshake `NewSessionTicket` messages immediately 
  following connection setup. Catching the specific mbedTLS return status 
  (-0x7B00 / MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) allows the app to 
  process the ticket and keep reading data streams safely.

* EXTENSION COMPLIANCE: Injected Application-Layer Protocol Negotiation (ALPN) 
  tokens ("http/1.1") directly into the client handshake profile. This satisfies 
  strict checking on modern edge firewalls that drop unnegotiated TLS 1.3 stacks.

* HTTP/1.1 STATE PARSER: Built a custom HTTP text engine processing across both 
  \r\n and \n boundaries. It separates header arrays from payload bytes, 
  detects redirect codes (301/302) to trigger loopback requests, and forces 
  uncompressed data delivery via `Accept-Encoding: identity`.

3. REPOSITORY BLUEPRINT
--------------------------------------------------------------------------------
* TLS13AppDelegate.m  -> Bootstraps the application window and splits display 
                          real estate to render a live on-screen log terminal.
* TLS13URLProtocol.m  -> Proxies WebKit, drives low-level mbedTLS sockets, parses 
                          uncompressed HTTP blocks, and yields clean data payloads.
* certs_bundle.h      -> Holds structural modern certificate chains compiled 
                          manually to replace the device's expired root storage.

================================================================================
