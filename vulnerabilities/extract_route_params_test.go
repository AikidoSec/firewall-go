package vulnerabilities

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractRouteParams(t *testing.T) {
	tests := []struct {
		name string
		path string
		want []string
	}{
		// Empty and root paths
		{name: "empty string", path: "", want: nil},
		{name: "root slash", path: "/", want: nil},

		// Normal alphanumeric paths — no results
		{name: "two-segment path", path: "/api/users", want: nil},
		{name: "multi-segment path", path: "/posts/comments", want: nil},
		{name: "versioned API path", path: "/v1/api/health", want: nil},
		{name: "no suspicious segments", path: "/api/v1/healthcheck", want: nil},
		{name: "alphanumeric mixed segment", path: "/a/b/abc2393027def/def", want: nil},
		{name: "trailing slash", path: "/app/shell/", want: nil},
		{name: "short trailing slash", path: "/app/", want: nil},

		// Segments that look like IDs but are pure alphanumeric — ignored
		{name: "numeric ID", path: "/api/users/123", want: nil},
		{name: "pure numbers", path: "/app/shell/12345", want: nil},
		{name: "pure numbers with alphanum suffix", path: "/app/shell/67890/abc", want: nil},
		{name: "MD5 hex hash", path: "/api/files/d41d8cd98f00b204e9800998ecf8427e", want: nil},
		{name: "BSON ObjectID", path: "/api/items/507f1f77bcf86cd799439011", want: nil},
		{name: "ULID", path: "/api/items/01ARZ3NDEKTSV4RRFFQ69G5FAV", want: nil},

		// URL-encoded characters: decoded segment + full path
		{
			name: "shell injection encoded",
			path: "/api/execute/ls%3Bcat%20%2Fetc%2Fpasswd",
			want: []string{"ls;cat /etc/passwd", "api/execute/ls%3Bcat%20%2Fetc%2Fpasswd"},
		},
		{
			name: "SQL injection encoded",
			path: "/api/users/1%27%20OR%201%3D1%20--",
			want: []string{"1' OR 1=1 --", "api/users/1%27%20OR%201%3D1%20--"},
		},
		{
			name: "encoded space detected via looksLikeASecret",
			path: "/api/search/hello%20world",
			want: []string{"hello world", "api/search/hello%20world"},
		},
		// Literal (unencoded) spaces in the path — r.URL.Path in Go is already decoded,
		// so these represent the realistic in-process form of URL-encoded requests.
		{
			name: "literal space in segment",
			path: "/app/shell/ls -la",
			want: []string{"ls -la", "app/shell/ls -la"},
		},
		{
			name: "literal space in segment simple",
			path: "/app/shell/space test",
			want: []string{"space test", "app/shell/space test"},
		},

		// Path traversal — dots trigger full-path inclusion
		{
			name: "dotdot traversal across segments",
			path: "/api/files/../../etc/passwd",
			want: []string{"api/files/../../etc/passwd"},
		},
		{
			name: "dotdot traversal encoded as single segment",
			path: "/api/files/..%2F..%2Fetc%2Fpasswd",
			want: []string{"api/files/..%2F..%2Fetc%2Fpasswd"},
		},
		{
			// The ".." segment itself isn't flagged as a route param, but the dot
			// in the decoded path triggers the full-path inclusion.
			name: "single dotdot segment",
			path: "/app/shell/..",
			want: []string{"app/shell/.."},
		},
		{
			// A single "." segment similarly causes the full path to be included.
			name: "single dot segment with trailing slash",
			path: "/app/shell/./",
			want: []string{"app/shell/./"},
		},

		// Recognised route-parameter patterns (non-alphanumeric, dynamic values)
		{
			name: "UUID",
			path: "/api/users/550e8400-e29b-41d4-a716-446655440000",
			want: []string{"550e8400-e29b-41d4-a716-446655440000", "api/users/550e8400-e29b-41d4-a716-446655440000"},
		},
		{
			name: "date YYYY-MM-DD",
			path: "/api/events/2024-01-15",
			want: []string{"2024-01-15", "api/events/2024-01-15"},
		},
		{
			name: "email address",
			path: "/api/users/user@example.com",
			want: []string{"user@example.com", "api/users/user@example.com"},
		},
		{
			name: "IPv4 address",
			path: "/api/hosts/192.168.1.1",
			want: []string{"192.168.1.1", "api/hosts/192.168.1.1"},
		},
		{
			name: "comma-separated numbers",
			path: "/api/items/1,2,3,4",
			want: []string{"1,2,3,4", "api/items/1,2,3,4"},
		},

		// Dot in path (filename extensions) triggers full-path inclusion
		{
			name: "filename with extension",
			path: "/api/files/config.json",
			want: []string{"api/files/config.json"},
		},
		{
			// "app." contains a dot so the full path is included, even though
			// the long alphanumeric suffix segment is ignored.
			// Note: Go does not add "app." as a separate result (unlike Python) because
			// url.PathEscape("app.") == "app." so the encoding check does not trigger,
			// and "app." does not match any route-parameter pattern.
			name: "dot-containing prefix segment with long alphanum suffix",
			path: "/app./shell/" + strings.Repeat("a", 1000),
			want: []string{"app./shell/" + strings.Repeat("a", 1000)},
		},
		{
			name: "dot-containing prefix segment with two long alphanum suffixes",
			path: "/app./shell/" + strings.Repeat("b", 1000) + strings.Repeat("/c", 1000),
			want: []string{"app./shell/" + strings.Repeat("b", 1000) + strings.Repeat("/c", 1000)},
		},

		// Multiple suspicious segments in one path
		{
			// "017shell" is alphanumeric and must be ignored between the two params.
			name: "email and IP with ignored alphanum segment between them",
			path: "/app/shell/test@example.org/017shell/127.0.0.1/",
			want: []string{"test@example.org", "127.0.0.1", "app/shell/test@example.org/017shell/127.0.0.1/"},
		},
		{
			name: "email followed by normal segment",
			path: "/api/users/user@example.com/posts",
			want: []string{"user@example.com", "api/users/user@example.com/posts"},
		},

		// Special characters that Go's PathEscape encodes (e.g. "!")
		{
			name: "special chars after alphanumeric segment",
			path: "/app/shell/abc123/!@",
			want: []string{"!@", "app/shell/abc123/!@"},
		},
		{
			name: "special chars after multiple ignored segments",
			path: "/app/shell/abc/123/!@",
			want: []string{"!@", "app/shell/abc/123/!@"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractRouteParams(tt.path))
		})
	}
}

func TestIsAlphanumeric(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"hello", true},
		{"Hello123", true},
		{"abc", true},
		{"123", true},
		{"d41d8cd98f00b204e9800998ecf8427e", true},
		{"017shell", true},
		{"", false},
		{"hello world", false},
		{"hello-world", false},
		{"hello.world", false},
		{"hello/world", false},
		{"!@#", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, isAlphanumeric(tt.input))
		})
	}
}

func TestLooksLikeASecret(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Too short
		{name: "empty string", input: "", want: false},
		{name: "single char", input: "c", want: false},
		{name: "too short", input: "abc", want: false},
		{name: "exactly minimum length", input: "OmNf04j6mU", want: false},

		// Missing required character classes
		{name: "no numbers", input: "abcdefghijklm", want: false},
		{name: "only lowercase and numbers", input: "abcdefg12345", want: false},
		{name: "only numbers", input: "1234567890", want: false},
		{name: "only numbers repeated", input: "12345678901234567890", want: false},

		// Word separators disqualify the string
		{name: "contains space", input: "abc 123 DEF!", want: false},
		{name: "contains space at end", input: "rsVEExrR2sVDONyeWwND ", want: false},
		{name: "contains dash", input: "abc-123-DEF!GHI", want: false},
		{name: "known word separator pattern", input: "this-is-a-secret-1", want: false},

		// Genuine secrets
		{name: "mixed case numbers and special chars", input: "aB3$dE6&hI0!kL", want: true},
		{name: "encoded space looks like secret", input: "hello%20world", want: true},
		{name: "long mixed secret", input: "rsVEExrR2sVDONyeWwND", want: true},
		{name: "long secret with special chars", input: ":2fbg;:qf$BRBc<2AG8&", want: true},
		{name: "very long secret", input: "efDJHhzvkytpXoMkFUgag6shWJktYZ5QUrUCTfecFELpdvaoAT3tekI4ZhpzbqLt", want: true},
		{name: "very long secret 2", input: "XqSwF6ySwMdTomIdmgFWcMVXWf5L0oVvO5sIjaCPI7EjiPvRZhZGWx3A6mLl1HXPOHdUeabsjhngW06JiLhAchFwgtUaAYXLolZn75WsJVKHxEM1mEXhlmZepLCGwRAM", want: true},
		{name: "known secret yqHYTS", input: "yqHYTS<agpi^aa1", want: true},
		{name: "known secret hIofuWBifkJI5", input: "hIofuWBifkJI5iVsSNKKKDpBfmMqJJwuXMxau6AS8WZaHVLDAMeJXo3BwsFyrIIm", want: true},
		{name: "known secret AG7DrGi3", input: "AG7DrGi3pDDIUU1PrEsj", want: true},
		{name: "known secret CnJ4", input: "CnJ4DunhYfv2db6T1FRfciRBHtlNKOYrjoz", want: true},
		{name: "known secret Gic", input: "Gic*EfMq:^MQ|ZcmX:yW1", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, looksLikeASecret(tt.input))
		})
	}
}

func TestLooksLikeASecret_CommonURLTerms(t *testing.T) {
	// Common URL path segments that must never be flagged as secrets.
	terms := []string{
		"development", "programming", "applications", "implementation",
		"environment", "technologies", "documentation", "demonstration",
		"configuration", "administrator", "visualization", "international",
		"collaboration", "opportunities", "functionality", "customization",
		"specifications", "optimization", "contributions", "accessibility",
		"subscription", "subscriptions", "infrastructure", "architecture",
		"authentication", "sustainability", "notifications", "announcements",
		"recommendations", "communication", "compatibility", "enhancement",
		"integration", "performance", "improvements", "introduction",
		"capabilities", "communities", "credentials", "permissions",
		"validation", "serialization", "deserialization", "throttling",
		"microservices", "endpoints", "encryption", "authorization",
		"multipart", "urlencoded", "postman", "signature",
		"rate-limiting", "load-balancer", "data-transfer", "bearer-token",
		"json-schema", "api-docs", "api-gateway",
		"poppins-bold-webfont.woff2", "karla-bold-webfont.woff2",
		"startEmailBasedLogin", "jenkinsFile", "ConnectionStrings.config",
		"coach", "login", "payment_methods", "activity_logs",
		"feedback_responses", "balance_transactions", "customer_sessions",
		"payment_intents", "billing_portal", "subscription_items",
		"namedLayouts", "PlatformAction", "quickActions", "queryLocator",
		"relevantItems", "parameterizedSearch",
	}

	for _, term := range terms {
		t.Run(term, func(t *testing.T) {
			assert.False(t, looksLikeASecret(term), "expected %q not to look like a secret", term)
		})
	}
}

func TestIsRouteParameter(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "empty string", input: "", want: false},
		{name: "plain word", input: "users", want: false},
		{name: "API segment", input: "api", want: false},
		// API version strings start with a letter so they are not route params
		{name: "API version v1", input: "v1", want: false},

		// Numbers
		{name: "multi-digit number", input: "123", want: true},
		{name: "two-digit number", input: "42", want: true},

		// Comma-separated numbers
		{name: "number array", input: "1,2,3,4", want: true},
		{name: "number array with thousands", input: "3,000", want: true},
		{name: "large number array", input: "200000,2,20000", want: true},
		{name: "number array leading comma", input: ",1,2,3,4", want: false},
		{name: "number array trailing comma", input: "0,1,2,3,4,", want: false},
		{name: "comma only", input: ",", want: false},

		// UUIDs — multiple versions
		{name: "UUID v1", input: "d9428888-122b-11e1-b85c-61cd3cbb3210", want: true},
		{name: "UUID v4", input: "550e8400-e29b-41d4-a716-446655440000", want: true},
		{name: "UUID v4 alternate", input: "109156be-c4fb-41ea-b1b4-efe1671c5836", want: true},
		// clock_seq_hi_and_res must be 8, 9, a, or b — 6 is invalid
		{name: "invalid UUID wrong clock_seq", input: "00000000-0000-1000-6000-000000000000", want: false},

		// ULIDs
		{name: "ULID uppercase", input: "01ARZ3NDEKTSV4RRFFQ69G5FAV", want: true},
		{name: "ULID lowercase", input: "01arz3ndektsv4rrffq69g5fav", want: true},
		{name: "ULID 27 chars", input: "01arz3ndektsv4rrffq69g5favv", want: false},
		{name: "ULID 25 chars", input: "01arz3ndektsv4rrffq69g5fa", want: false},

		// BSON ObjectIDs (24-char hex)
		{name: "BSON ObjectID", input: "507f1f77bcf86cd799439011", want: true},
		{name: "BSON ObjectID alternate", input: "66ec29159d00113616fc7184", want: true},
		{name: "BSON ObjectID 25 chars", input: "66ec29159d00113616fc71845", want: false},
		{name: "BSON ObjectID 23 chars", input: "66ec29159d00113616fc718", want: false},

		// Dates
		{name: "date YYYY-MM-DD", input: "2024-01-15", want: true},
		{name: "date DD-MM-YYYY", input: "15-01-2024", want: true},

		// Emails
		{name: "email address", input: "user@example.com", want: true},
		{name: "email with subdomain", input: "john.doe@acme.com", want: true},
		{name: "email with plus alias", input: "john.doe+alias@acme.com", want: true},

		// IPv4
		{name: "IPv4 address", input: "192.168.1.1", want: true},
		{name: "IPv4 alternate", input: "227.202.96.196", want: true},
		// IPv6 is not detected — Go's regex only covers IPv4
		{name: "IPv6 address not detected", input: "2001:2:ffff:ffff:ffff:ffff:ffff:ffff", want: false},

		// Hashes (MD5=32, SHA1=40, SHA256=64, SHA512=128)
		{name: "MD5 hash", input: "098f6bcd4621d373cade4e832627b4f6", want: true},
		{name: "SHA1 hash", input: "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", want: true},
		{name: "SHA256 hash", input: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", want: true},
		{name: "SHA512 hash", input: "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", want: true},

		// Secret tokens (via looksLikeASecret)
		{name: "secret token", input: "CnJ4DunhYfv2db6T1FRfciRBHtlNKOYrjoz", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isRouteParameter(tt.input))
		})
	}
}
