package oauth

import (
	"slices"
	"strings"
)

// ParseScope splits a space-delimited scope string (RFC 6749 §3.3) into its
// values, dropping empty entries and duplicates while preserving order.
func ParseScope(s string) []string {
	if s == "" {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, v := range strings.Fields(s) {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// FormatScope joins scope values back into the wire format.
func FormatScope(scopes []string) string {
	return strings.Join(scopes, " ")
}

// ScopeIsSubset reports whether every value in sub also appears in super.
// It is the narrowing rule for refresh and token-exchange grants: a derived
// token may shrink scope, never widen it. An empty sub is a subset of
// anything.
func ScopeIsSubset(sub, super []string) bool {
	superSet := make(map[string]bool, len(super))
	for _, s := range super {
		superSet[s] = true
	}
	for _, s := range sub {
		if !superSet[s] {
			return false
		}
	}
	return true
}

// ScopeContains reports whether list includes s.
func ScopeContains(list []string, s string) bool {
	return slices.Contains(list, s)
}
