package helpers

import (
	"github.com/stretchr/testify/assert"
	"math/rand"
	"strings"
	"testing"
)

const (
	lower    = "abcdefghijklmnopqrstuvwxyz"
	upper    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numbers  = "0123456789"
	specials = "!#$%^&*|;:<>"
)

func secretFromCharset(length int, charset string) string {
	result := make([]rune, length)
	for i := 0; i < length; i++ {
		result[i] = rune(charset[randomInt(0, len(charset))])
	}
	return string(result)
}

func randomInt(min, max int) int {
	return min + rand.Intn(max-min)
}

func TestLooksLikeASecret(t *testing.T) {
	t.Run("it returns false for empty string", func(t *testing.T) {
		assert.False(t, LooksLikeASecret(""))
	})

	t.Run("it returns false for short strings", func(t *testing.T) {
		shortStrings := []string{
			"c", "NR", "7t3", "4qEK", "KJr6s", "KXiW4a", "Fupm2Vi", "jiGmyGfg",
			"SJPLzVQ8t", "OmNf04j6mU",
		}
		for _, str := range shortStrings {
			assert.False(t, LooksLikeASecret(str))
		}
	})

	t.Run("it returns true for long strings", func(t *testing.T) {
		assert.True(t, LooksLikeASecret("rsVEExrR2sVDONyeWwND"))
		assert.True(t, LooksLikeASecret(":2fbg;:qf$BRBc<2AG8&"))
	})

	t.Run("it flags very long strings", func(t *testing.T) {
		assert.True(t, LooksLikeASecret("efDJHhzvkytpXoMkFUgag6shWJktYZ5QUrUCTfecFELpdvaoAT3tekI4ZhpzbqLt"))
	})

	t.Run("it flags very very long strings", func(t *testing.T) {
		assert.True(t, LooksLikeASecret("XqSwF6ySwMdTomIdmgFWcMVXWf5L0oVvO5sIjaCPI7EjiPvRZhZGWx3A6mLl1HXPOHdUeabsjhngW06JiLhAchFwgtUaAYXLolZn75WsJVKHxEM1mEXhlmZepLCGwRAM"))
	})

	t.Run("it returns false if contains white space", func(t *testing.T) {
		assert.False(t, LooksLikeASecret("rsVEExrR2sVDONyeWwND "))
	})

	t.Run("it returns false if it has less than 2 charsets", func(t *testing.T) {
		assert.False(t, LooksLikeASecret(secretFromCharset(10, lower)))
		assert.False(t, LooksLikeASecret(secretFromCharset(10, upper)))
		assert.False(t, LooksLikeASecret(secretFromCharset(10, numbers)))
		assert.False(t, LooksLikeASecret(secretFromCharset(10, specials)))
	})

	urlTerms := []string{
		"development", "programming", "applications", "implementation", "environment",
		"technologies", "documentation", "demonstration", "configuration", "administrator",
		"visualization", "international", "collaboration", "opportunities", "functionality",
		"customization", "specifications", "optimization", "contributions", "accessibility",
		"subscription", "subscriptions", "infrastructure", "architecture", "authentication",
		"sustainability", "notifications", "announcements", "recommendations", "communication",
		"compatibility", "enhancement", "integration", "performance", "improvements",
		"introduction", "capabilities", "communities", "credentials", "integration",
		"permissions", "validation", "serialization", "deserialization", "rate-limiting",
		"throttling", "load-balancer", "microservices", "endpoints", "data-transfer",
		"encryption", "authorization", "bearer-token", "multipart", "urlencoded",
		"api-docs", "postman", "json-schema", "serialization", "deserialization",
		"rate-limiting", "throttling", "load-balancer", "api-gateway", "microservices",
		"endpoints", "data-transfer", "encryption", "signature", "poppins-bold-webfont.woff2",
		"karla-bold-webfont.woff2", "startEmailBasedLogin", "jenkinsFile", "ConnectionStrings.config",
		"coach", "login", "payment_methods", "activity_logs", "feedback_responses",
		"balance_transactions", "customer_sessions", "payment_intents", "billing_portal",
		"subscription_items", "namedLayouts", "PlatformAction", "quickActions", "queryLocator",
		"relevantItems", "parameterizedSearch",
	}

	t.Run("it returns false for common url terms", func(t *testing.T) {
		for _, term := range urlTerms {
			assert.False(t, LooksLikeASecret(term), "Expected %s to not look like a secret", term)
		}
	})

	t.Run("it returns false for known word separators", func(t *testing.T) {
		assert.False(t, LooksLikeASecret("this-is-a-secret-1"))
	})

	t.Run("a number is not a secret", func(t *testing.T) {
		assert.False(t, LooksLikeASecret("1234567890"))
		assert.False(t, LooksLikeASecret(strings.Repeat("1234567890", 2)))
	})

	secrets := []string{
		"yqHYTS<agpi^aa1",
		"hIofuWBifkJI5iVsSNKKKDpBfmMqJJwuXMxau6AS8WZaHVLDAMeJXo3BwsFyrIIm",
		"AG7DrGi3pDDIUU1PrEsj",
		"CnJ4DunhYfv2db6T1FRfciRBHtlNKOYrjoz",
		"Gic*EfMq:^MQ|ZcmX:yW1",
		"AG7DrGi3pDDIUU1PrEsj",
	}

	t.Run("it returns true for known secrets", func(t *testing.T) {
		for _, secret := range secrets {
			assert.True(t, LooksLikeASecret(secret), "Expected %s to look like a secret", secret)
		}
	})
}
