# Security Patch Summary: IP Authorization Header Spoofing Fix

## Issue
IP allow/block enforcement was vulnerable to header spoofing attacks. Attackers could bypass IP restrictions by forging `X-Forwarded-For` headers with allowlisted IPs.

## Root Cause
The firewall used header-derived client IPs for authorization decisions without validating that requests came from trusted proxies. The `AIKIDO_TRUST_PROXY` setting (default: `true`) was insufficient because it didn't distinguish between logging/monitoring use cases and security-critical authorization decisions.

## Solution
Implemented a secure-by-default approach that separates client IP derivation for different purposes:

### 1. New Authorization IP Function
- **File**: `instrumentation/http/ip_from_request.go`
- **Function**: `GetClientIPForAuthorization()`
- **Behavior**: Uses socket IP by default; only trusts headers when `AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS=true`

### 2. New Environment Variable
- **Name**: `AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS`
- **Default**: `false` (secure by default)
- **Purpose**: Explicitly opt-in to trusting proxy headers for authorization decisions

### 3. Context Changes
- **Files**: 
  - `internal/request/context.go`
  - `internal/request/http_context.go`
  - `instrumentation/request/context.go`
- **Changes**: Added `AuthorizationIP` field to store the IP for authorization decisions
- **New Method**: `GetIPForAuthorization()` to retrieve the authorization IP

### 4. Middleware Updates
Updated all middleware to populate both IPs:
- `instrumentation/sources/net/http/middleware.go`
- `instrumentation/sources/gin-gonic/gin/middleware.go`
- `instrumentation/sources/go-chi/chi.v5/middleware.go`
- `instrumentation/sources/labstack/echo.v4/middleware.go`
- `instrumentation/sources/labstack/echo.v5/middleware.go`

Each middleware now calls:
```go
ip := GetClientIP(r)                    // For logging/monitoring
authIP := GetClientIPForAuthorization(r) // For authorization
```

### 5. Authorization Enforcement
- **File**: `instrumentation/http/on_init_request.go`
- **Change**: All IP-based security checks now use `reqCtx.GetIPForAuthorization()`
- **Affected Checks**:
  - `IsIPAllowed()` - Global IP allow list
  - `IsIPBlocked()` - Global IP block list
  - `ipAllowedToAccessRoute()` - Per-route IP allow list
  - `GetMatchingMonitoredIPKeys()` - IP monitoring

## Security Impact

### Before Fix
```
Attacker Request:
  Socket IP: 1.2.3.4 (blocked)
  X-Forwarded-For: 5.6.7.8 (allowed)
  
Firewall Decision: ALLOWED ❌ (uses header)
```

### After Fix (Default)
```
Attacker Request:
  Socket IP: 1.2.3.4 (blocked)
  X-Forwarded-For: 5.6.7.8 (allowed)
  
Firewall Decision: BLOCKED ✓ (uses socket IP)
```

### After Fix (With Trusted Proxy)
```
Legitimate Request via Trusted Proxy:
  Socket IP: 10.0.0.1 (proxy)
  X-Forwarded-For: 5.6.7.8 (real client, allowed)
  AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS: true
  
Firewall Decision: ALLOWED ✓ (uses header, explicitly trusted)
```

## Backward Compatibility

### Maintained
- `GetClientIP()` behavior unchanged (still uses headers by default)
- Logging and monitoring continue to use header-derived IPs
- No breaking changes to existing APIs

### Changed (Security Improvement)
- IP authorization now uses socket IP by default
- Users behind reverse proxies may need to set `AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS=true`

## Testing

### New Test Files
1. `instrumentation/http/ip_from_request_authorization_test.go`
   - Tests for `GetClientIPForAuthorization()` function
   - Validates default secure behavior
   - Tests explicit opt-in to trust proxy headers

2. `instrumentation/http/on_init_request_authorization_test.go`
   - End-to-end tests for IP authorization
   - Validates header spoofing prevention
   - Tests allow/block list enforcement

### Test Coverage
- Default behavior (socket IP for authorization)
- Explicit trust proxy setting
- Header spoofing attack scenarios
- Private IP handling
- Custom header support
- Integration with allow/block lists

## Files Modified

### Core Logic
1. `instrumentation/http/ip_from_request.go` - Added `GetClientIPForAuthorization()` and `isTrustProxyForIPRestrictions()`
2. `instrumentation/http/on_init_request.go` - Updated to use authorization IP

### Context/Data Structures
3. `internal/request/context.go` - Added `AuthorizationIP` field and `GetIPForAuthorization()` method
4. `internal/request/http_context.go` - Updated `ContextData` and `SetContext()`
5. `instrumentation/request/context.go` - Updated public `ContextData` and `SetContext()`

### Middleware
6. `instrumentation/sources/net/http/middleware.go`
7. `instrumentation/sources/gin-gonic/gin/middleware.go`
8. `instrumentation/sources/go-chi/chi.v5/middleware.go`
9. `instrumentation/sources/labstack/echo.v4/middleware.go`
10. `instrumentation/sources/labstack/echo.v5/middleware.go`

### Tests
11. `instrumentation/http/ip_from_request_authorization_test.go` (new)
12. `instrumentation/http/on_init_request_authorization_test.go` (new)

### Documentation
13. `SECURITY_FIX_IP_AUTHORIZATION.md` (new)

## Deployment Recommendations

### For Most Users
- Deploy immediately - secure by default
- No configuration changes needed

### For Users Behind Reverse Proxies
1. Deploy the fix
2. Test IP restrictions
3. If restrictions are too strict, set `AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS=true`
4. Verify that untrusted clients cannot directly connect to your application

### For Users with Direct Internet Exposure
- Deploy immediately - maximum security benefit
- No configuration changes needed

## Verification

To verify the fix is working:

1. **Without trusted proxy** (default):
   ```bash
   curl -H "X-Forwarded-For: <allowlisted-ip>" http://your-app/
   # Should be blocked if your real IP is not in the allow list
   ```

2. **With trusted proxy**:
   ```bash
   export AIKIDO_TRUST_PROXY_FOR_IP_RESTRICTIONS=true
   # Restart application
   curl -H "X-Forwarded-For: <allowlisted-ip>" http://your-app/
   # Should be allowed if the header IP is in the allow list
   ```

## References
- Pentest Finding: "IP allow/block enforcement uses a spoofable forwarded client-IP header"
- OWASP: IP Address Spoofing
- RFC 7239: Forwarded HTTP Extension
