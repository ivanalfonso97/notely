package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "ApiKey secret-124")

	key, err := GetAPIKey(h)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if key != "secret-123" {
		t.Fatalf("expected key %q, got %q", "secret-123", key)
	}
}

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	h := http.Header{} // no Authorization header

	_, err := GetAPIKey(h)
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"WrongScheme", "Bearer abc"},
		{"MissingToken", "ApiKey"},
		{"Empty", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.value != "" {
				h.Set("Authorization", tc.value)
			}

			_, err := GetAPIKey(h)
			if tc.value == "" {
				// Empty is handled as "no header"
				if !errors.Is(err, ErrNoAuthHeaderIncluded) {
					t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
				}
				return
			}

			if err == nil || err.Error() != "malformed authorization header" {
				t.Fatalf("expected %q error, got %v", "malformed authorization header", err)
			}
		})
	}
}
