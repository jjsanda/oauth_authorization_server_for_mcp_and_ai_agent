// Command authserver runs the OAuth 2.1 authorization server.
//
// Configuration (flags override environment variables):
//
//	-addr    / AUTH_ADDR              listen address        (default :9000)
//	-issuer  / AUTH_ISSUER            public issuer URL     (default http://localhost:9000)
//	-alg     / AUTH_SIGNING_ALG       ES256 or EdDSA        (default ES256)
//	-key     / AUTH_SIGNING_KEY_FILE  PKCS#8 PEM file; ephemeral key when unset
//	-resources / DEMO_RESOURCES       comma-separated resource IDs the demo
//	                                  clients may request  (default the two
//	                                  compose resource servers)
//	           LOG_LEVEL              debug|info|warn|error (default info)
//	           LOG_FORMAT             text|json             (default text)
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
	"time"

	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/authserver"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/httpx"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/jose"
	"github.com/jjsanda/oauth_authorization_server_for_mcp_and_ai_agent/internal/store/memory"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func run() error {
	var (
		addr      = flag.String("addr", envOr("AUTH_ADDR", ":9000"), "listen address")
		issuer    = flag.String("issuer", envOr("AUTH_ISSUER", "http://localhost:9000"), "public issuer URL")
		alg       = flag.String("alg", envOr("AUTH_SIGNING_ALG", "ES256"), "signing algorithm: ES256 or EdDSA")
		keyFile   = flag.String("key", envOr("AUTH_SIGNING_KEY_FILE", ""), "PKCS#8 PEM signing key (ephemeral when unset)")
		resources = flag.String("resources", envOr("DEMO_RESOURCES", "http://localhost:9100,http://localhost:9200"),
			"comma-separated resource identifiers the demo clients may request")
		healthcheck = flag.Bool("healthcheck", false, "probe the local server's /healthz and exit (for container health checks)")
	)
	flag.Parse()

	if *healthcheck {
		return httpx.SelfProbe("http://127.0.0.1" + normalizeAddr(*addr) + "/healthz")
	}

	log := httpx.NewLogger(envOr("LOG_LEVEL", "info"), envOr("LOG_FORMAT", "text"))
	slog.SetDefault(log)

	var keys *jose.KeySet
	if *keyFile != "" {
		pemBytes, err := os.ReadFile(*keyFile)
		if err != nil {
			return fmt.Errorf("read signing key: %w", err)
		}
		key, err := jose.ParsePrivateKeyPEM(pemBytes)
		if err != nil {
			return err
		}
		keys = jose.NewKeySetWithKey(key)
	} else {
		var err error
		keys, err = jose.NewKeySet(jose.Algorithm(*alg))
		if err != nil {
			return err
		}
		log.Warn("using an ephemeral signing key; tokens will not survive restarts",
			slog.String("alg", *alg), slog.String("kid", keys.Active().KID))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st := memory.New()
	st.StartJanitor(ctx, time.Minute)
	resourceList := splitResources(*resources)
	srv := authserver.New(authserver.Config{
		Issuer:    *issuer,
		Resources: resourceList,
	}, st, keys, log)
	authserver.SeedDemo(st, resourceList, nil)

	log.Info("authorization server starting",
		slog.String("issuer", *issuer),
		slog.String("alg", string(keys.Active().Alg)),
		slog.Any("demo_resources", resourceList))
	return httpx.Run(ctx, httpx.NewServer(*addr, srv.Routes()), log)
}

// splitResources parses the comma-separated resource list, trimming spaces
// and dropping empty entries so a stray comma cannot seed a client allowed
// for the empty resource.
func splitResources(s string) []string {
	var out []string
	for _, r := range strings.Split(s, ",") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
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

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "authserver:", err)
		os.Exit(1)
	}
}
