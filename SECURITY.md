# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `go-iec104`, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email **security@otfabric.com**, or open a private advisory on GitHub (the [Security](https://github.com/otfabric/go-iec104/security) tab → **Advisories** → **Report a vulnerability**), with:

- A description of the vulnerability
- Steps to reproduce the issue, ideally a minimal program or test
- The affected version(s)
- Any potential impact you've identified

We will acknowledge your report within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Older releases | Best effort |

## Security Considerations

### IEC 60870-5-104 Has No Built-In Security

Plain IEC 60870-5-104 carries no authentication and no encryption: anyone who can reach a station on port 2404 can interrogate it and send it commands, and anyone on the path can read or alter the traffic. The commands operate physical equipment.

- **Keep plain IEC 104 traffic on isolated, trusted networks**; never expose port 2404 to the Internet
- **Use TLS across untrusted networks** (`client.WithTLS`, `server.WithTLS`), or put a VPN or secured gateway in front of the station

### TLS (IEC 62351-3)

- `server.WithTLS` and `client.WithTLS` take a standard `*tls.Config`; the library does not weaken or override it. Set `MinVersion` to TLS 1.2 or later
- For mutual authentication set `ClientAuth: tls.RequireAndVerifyClientCert` and `ClientCAs` on the server and `Certificates` on the client. Without it a TLS server still accepts commands from any client
- Authorization is the handler's job: `Session.Conn()` returns the `*tls.Conn`, whose `ConnectionState().PeerCertificates` identifies the controlling station
- Keep private keys out of source control and give key files restrictive permissions (`chmod 600`)
- The application-layer authentication of IEC 62351-5 (challenge/response on critical ASDUs) is **not** implemented

### Hardening a Server

- `server.WithAccept` restricts which addresses may connect; it is checked before any protocol exchange. Treat it as defence in depth: a source address is not an identity
- `server.WithMaxSessions` bounds the number of simultaneous connections
- `server.WithCommonAddrs` rejects ASDUs for stations the server does not represent
- Validate every command in the handler (address, value range, select-before-operate state, interlocks) before acting on the process. The library checks the encoding, not the meaning

### Input Handling

- Every received APDU and ASDU is length- and structure-checked before use; malformed input closes the connection (APDU) or is dropped (ASDU) and cannot cause a panic. The decoders are fuzzed
- Memory per connection is bounded: frames are at most 255 octets, and a slow handler stops acknowledgements and ultimately reading instead of queueing without limit
- A TLS handshake must complete within `t0`; a peer that connects and stays silent does not hold a session
- A panic in a server handler closes that session only
