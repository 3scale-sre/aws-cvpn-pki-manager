package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	"github.com/spf13/viper"
)

func TestAuthMiddleware(t *testing.T) {
	viper.Set("auth-github-org", "test-org")
	t.Cleanup(viper.Reset)

	tests := []struct {
		name   string
		path   string
		method string
		want   int
	}{
		{"healthz is exempt", "/healthz", http.MethodGet, http.StatusOK},
		{"readyz is exempt", "/readyz", http.MethodGet, http.StatusOK},
		{"issue for user ending in z is enforced", "/issue/alicez", http.MethodPost, http.StatusUnauthorized},
		{"revoke for user ending in z is enforced", "/revoke/liz", http.MethodPost, http.StatusUnauthorized},
		{"nested probe name is enforced", "/x/healthz", http.MethodGet, http.StatusUnauthorized},
		{"probe with trailing slash is enforced", "/healthz/", http.MethodGet, http.StatusUnauthorized},
		{"regular endpoint is enforced", "/users", http.MethodGet, http.StatusUnauthorized},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := authMiddleware(next, logr.Discard())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			// Malformed header: rejected before any call to the GitHub API.
			req.Header.Set("Authorization", "invalid")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("%s %s: got status %d, want %d", tt.method, tt.path, rec.Code, tt.want)
			}
		})
	}
}
