// Command resourceserver runs an MCP-style protected resource server. The
// demo deployment runs two instances of this binary with different
// configuration: a "tools" API and a "reports" API, so that audience
// restriction and token exchange have two distinct targets.
//
// Configuration (flags override environment variables):
//
//	-addr       / RS_ADDR         listen address                 (default :9100)
//	-resource   / RS_RESOURCE     own RFC 8707 resource ID       (default http://localhost:9100)
//	-issuer     / RS_ISSUER       trusted authorization server   (default http://localhost:9000)
//	-scope-list / RS_SCOPE_LIST   scope required for tools/list  (default tools:read)
//	-scope-call / RS_SCOPE_CALL   scope required for tools/call  (default tools:invoke)
//	              LOG_LEVEL       debug|info|warn|error          (default info)
//	              LOG_FORMAT      text|json                      (default text)
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/httpx"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/resourceserver"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func normalizeAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return addr
	}
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[i:]
	}
	return ":" + addr
}

func run() error {
	var (
		addr      = flag.String("addr", envOr("RS_ADDR", ":9100"), "listen address")
		resource  = flag.String("resource", envOr("RS_RESOURCE", "http://localhost:9100"), "this server's resource identifier")
		issuer    = flag.String("issuer", envOr("RS_ISSUER", "http://localhost:9000"), "trusted authorization server issuer URL")
		scopeList = flag.String("scope-list", envOr("RS_SCOPE_LIST", "tools:read"), "scope required to list tools")
		scopeCall = flag.String("scope-call", envOr("RS_SCOPE_CALL", "tools:invoke"), "scope required to call tools")

		healthcheck = flag.Bool("healthcheck", false, "probe the local server's /healthz and exit (for container health checks)")
	)
	flag.Parse()

	if *healthcheck {
		return httpx.SelfProbe("http://127.0.0.1" + normalizeAddr(*addr) + "/healthz")
	}

	log := httpx.NewLogger(envOr("LOG_LEVEL", "info"), envOr("LOG_FORMAT", "text"))
	slog.SetDefault(log)

	srv := resourceserver.New(resourceserver.Config{
		Resource:  *resource,
		Issuer:    *issuer,
		ScopeList: *scopeList,
		ScopeCall: *scopeCall,
	}, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("resource server starting",
		slog.String("resource", *resource),
		slog.String("issuer", *issuer))
	return httpx.Run(ctx, httpx.NewServer(*addr, srv.Routes()), log)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "resourceserver:", err)
		os.Exit(1)
	}
}
