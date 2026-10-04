// Package httpx provides small HTTP server building blocks shared by the
// authorization server and the resource server: hardened server defaults,
// graceful shutdown, and middleware for request IDs, logging, panic
// recovery, and security headers.
package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"
)

// Middleware wraps an http.Handler with additional behavior.
type Middleware func(http.Handler) http.Handler

// Chain applies middlewares to h in the given order: the first middleware
// listed is the outermost one at request time.
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

type ctxKey int

const (
	ctxKeyRequestID ctxKey = iota
	ctxKeyLogger
)

// RequestID assigns a random ID to every request, exposes it via the request
// context and echoes it in the X-Request-Id response header so log lines can
// be correlated with client-observed responses.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf [8]byte
		if _, err := rand.Read(buf[:]); err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		id := hex.EncodeToString(buf[:])
		w.Header().Set("X-Request-Id", id)
		ctx := context.WithValue(r.Context(), ctxKeyRequestID, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestIDFrom returns the request ID stored by the RequestID middleware,
// or "" when absent.
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(ctxKeyRequestID).(string)
	return id
}

// WithLogger stores a base logger in the request context, pre-tagged with
// the request ID when one is present.
func WithLogger(base *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			l := base
			if id := RequestIDFrom(r.Context()); id != "" {
				l = l.With(slog.String("request_id", id))
			}
			ctx := context.WithValue(r.Context(), ctxKeyLogger, l)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Logger returns the request-scoped logger, falling back to slog.Default.
func Logger(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKeyLogger).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

// statusRecorder captures the response status code for access logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

// AccessLog emits one structured log line per request.
func AccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		Logger(r.Context()).Info("http_request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.status),
			slog.Duration("duration", time.Since(start)),
			slog.String("remote", r.RemoteAddr),
		)
	})
}

// Recover converts panics into 500 responses instead of tearing down the
// connection, and logs the panic value.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				Logger(r.Context()).Error("panic recovered", slog.Any("panic", v))
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// SecureHeaders sets response headers that are safe defaults for both JSON
// APIs and the small HTML pages served by the authorization server.
func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
