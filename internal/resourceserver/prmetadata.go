package resourceserver

import (
	"encoding/json"
	"net/http"
)

// protectedResourceMetadata is the RFC 9728 document. Its
// authorization_servers list is what lets a client that received a bare 401
// bootstrap the entire OAuth conversation.
type protectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
}

func (s *Server) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	doc := protectedResourceMetadata{
		Resource:             s.cfg.Resource,
		AuthorizationServers: []string{s.cfg.Issuer},
		ScopesSupported:      s.cfg.ScopesSupported,
		// Tokens are accepted only in the Authorization header — never in
		// query strings (they leak into logs) or form bodies.
		BearerMethodsSupported: []string{"header"},
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	_ = json.NewEncoder(w).Encode(doc)
}
