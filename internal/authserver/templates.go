package authserver

import (
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates/*.html
var templateFS embed.FS

var templates = template.Must(template.ParseFS(templateFS, "templates/*.html"))

// renderPage writes an HTML page with a strict content security policy: no
// scripts, no external resources, inline styles only.
func (s *Server) renderPage(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html;charset=UTF-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("template render failed", "template", name, "error", err)
	}
}

// renderErrorPage shows a local error page. Used whenever redirecting back
// to the client would be unsafe (unknown client, invalid redirect URI).
func (s *Server) renderErrorPage(w http.ResponseWriter, status int, title, message string) {
	s.renderPage(w, status, "error", struct {
		Title   string
		Message string
	}{title, message})
}
