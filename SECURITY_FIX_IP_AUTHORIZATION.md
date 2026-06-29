# IP Authorization Security Fix

## Overview

This document describes the security fix implemented to prevent IP allow/block bypass attacks through header spoofing.

## Vulnerability

Prior to this fix, the firewall used the client IP derived from HTTP headers (e.g., `X-Forwarded-For`) for IP-based authorization decisions (allow/block lists) without validating that the request actually came from a trusted proxy. This allowed attackers to bypass IP restrictions by forging headers:

```
# Attacker request with spoofed header
X-Forwarded-For: <allowlisted-ip>
```

The firewall would use the spoofed IP for authorization checks, allowing the attacker to bypass restrictions.

## Fix

The fix introduces a separation between:

1. **Client IP for logging/monitoring** (`GetClientIP()`) - May use headers when `AIKIDO_TRUST_PROXY=true` (default)
2. **Client IP for authorization** (`GetClientIPForAuthorization()`) - Uses socket IP by default for security

### Key Changes

1. **New function**: `GetClientIPForAuthorization()` in `instrumentation/http/ip_from_request.go`
   - Returns the TCP socket IP by default (cannot be spoofed)
   - Only trusts proxy headers when `AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS=true` is explicitly set

2. **New environment variable**: `AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS`
   - Default: `false` (secure by default)
   - Set to `true` only if your application is behind a trusted reverse proxy AND you need to enforce IP restrictions based on client IPs from proxy headers
   - **WARNING**: Setting this to `true` without proper proxy configuration allows attackers to bypass IP restrictions

3. **Context changes**: Added `AuthorizationIP` field to request context
   - Stores the IP to use for authorization decisions
   - Populated by middleware using `GetClientIPForAuthorization()`

4. **Authorization enforcement**: Updated `OnInitRequest()` to use `GetIPForAuthorization()`
   - All IP allow/block checks now use the authorization IP
   - Prevents header spoofing attacks

### Affected Components

- `instrumentation/http/ip_from_request.go` - New authorization IP function
- `instrumentation/http/on_init_request.go` - Uses authorization IP for checks
- `internal/request/context.go` - Added `AuthorizationIP` field and `GetIPForAuthorization()` method
- All middleware files:
  - `instrumentation/sources/net/http/middleware.go`
  - `instrumentation/sources/gin-gonic/gin/middleware.go`
  - `instrumentation/sources/go-chi/chi.v5/middleware.go`
  - `instrumentation/sources/labstack/echo.v4/middleware.go`
  - `instrumentation/sources/labstack/echo.v5/middleware.go`

## Configuration

### Default Behavior (Secure)

By default, IP authorization uses the socket IP:

```go
// No configuration needed - secure by default
// Authorization checks use socket IP (cannot be spoofed)
```

### Behind a Trusted Reverse Proxy

If your application is behind a trusted reverse proxy (e.g., AWS ALB, nginx, Cloudflare) and you need to enforce IP restrictions based on the real client IP:

```bash
export AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS=true
```

**Important**: Only enable this if:
1. Your application is behind a trusted reverse proxy
2. The proxy is properly configured to set forwarded headers
3. Untrusted clients cannot directly connect to your application
4. You need to enforce IP restrictions based on the real client IP (not the proxy IP)

### Custom Header

If your proxy uses a custom header for the client IP:

```bash
export AIKIDO_CLIENT_IP_HEADER=X-Real-IP
export AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS=true
```

## Migration Guide

### For Most Users

No action required. The fix is secure by default and maintains backward compatibility for logging and monitoring.

### For Users Behind Reverse Proxies

If you have IP allow/block lists configured and your application is behind a reverse proxy:

1. **Test your setup**: Verify that IP restrictions still work as expected
2. **If restrictions are too strict**: Set `AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS=true`
3. **Verify security**: Ensure untrusted clients cannot directly connect to your application

### For Users with Direct Internet Exposure

If your application is directly exposed to the internet (no reverse proxy):

- No action required
- The fix automatically uses the socket IP for authorization
- Attackers cannot bypass IP restrictions by forging headers

## Testing

The fix includes comprehensive tests:

- `instrumentation/http/ip_from_request_authorization_test.go` - Tests for `GetClientIPForAuthorization()`
- `instrumentation/http/on_init_request_authorization_test.go` - End-to-end tests for IP authorization

Run tests:

```bash
go test ./instrumentation/http/...
```

## Security Considerations

### Why Two Separate Functions?

1. **Logging/Monitoring** (`GetClientIP()`):
   - May use headers for better visibility into real client IPs
   - Spoofing is less critical (doesn't affect security decisions)
   - Maintains backward compatibility

2. **Authorization** (`GetClientIPForAuthorization()`):
   - Must use trustworthy source (socket IP by default)
   - Spoofing would bypass security controls
   - Secure by default

### Defense in Depth

Even with this fix, consider additional security measures:

1. **Network segmentation**: Ensure untrusted clients cannot directly connect to your application
2. **Proxy validation**: Configure your reverse proxy to strip/overwrite forwarded headers
3. **Rate limiting**: Implement rate limiting based on socket IP
4. **Monitoring**: Monitor for suspicious patterns in forwarded headers

## References

- [OWASP: IP Address Spoofing](https://owasp.org/www-community/attacks/IP_Address_Spoofing)
- [RFC 7239: Forwarded HTTP Extension](https://tools.ietf.org/html/rfc7239)
- [X-Forwarded-For Header Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For#security_and_privacy_concerns)
