// Command agent is a demo OAuth 2.1 client behaving like an AI agent that
// wants to use MCP-style tool servers. Given nothing but a resource URL it
// discovers the authorization server, registers itself, obtains an
// audience-restricted token, calls the protected tools, and (optionally)
// demonstrates token exchange and refresh-token reuse detection.
//
//	agent -resource http://localhost:9100 -mode headless \
//	      -exchange-for http://localhost:9200 -demo-refresh-replay
//
// Modes:
//
//	headless            scripted login as the demo user (CI-friendly)
//	auth-code           prints a URL for a human to approve in a browser
//	client-credentials  machine-to-machine, no user involved
//
// The process exits non-zero if any step deviates from the protocol, which
// makes a successful run a meaningful end-to-end assertion.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/agent"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	os.Exit(run())
}

func run() int {
	var (
		resource    = flag.String("resource", envOr("AGENT_RESOURCE", "http://localhost:9100"), "protected resource to use")
		mode        = flag.String("mode", envOr("AGENT_MODE", "headless"), "headless | auth-code | client-credentials")
		exchangeFor = flag.String("exchange-for", envOr("AGENT_EXCHANGE_FOR", ""), "second resource to demonstrate RFC 8693 token exchange against")
		demoReplay  = flag.Bool("demo-refresh-replay", envOr("AGENT_DEMO_REFRESH_REPLAY", "") == "true", "demonstrate refresh rotation and reuse detection")
		username    = flag.String("username", envOr("AGENT_USERNAME", "alice"), "demo user for headless login")
		password    = flag.String("password", envOr("AGENT_PASSWORD", "password"), "demo user password")
		timeout     = flag.Duration("timeout", 5*time.Minute, "overall scenario timeout")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	err := agent.Run(ctx, agent.Options{
		Resource:          *resource,
		Mode:              agent.Mode(*mode),
		ExchangeFor:       *exchangeFor,
		DemoRefreshReplay: *demoReplay,
		Username:          *username,
		Password:          *password,
		Out:               os.Stdout,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "\nagent: FAILED:", err)
		return 1
	}
	return 0
}
