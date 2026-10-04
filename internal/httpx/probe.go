package httpx

import (
	"fmt"
	"net/http"
	"time"
)

// SelfProbe performs a one-shot health check against the given URL and
// returns nil on HTTP 200. It exists so the distroless container images —
// which have no shell, curl, or wget — can use their own binary as the
// Docker HEALTHCHECK command.
func SelfProbe(url string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health probe: %s returned %s", url, resp.Status)
	}
	return nil
}
