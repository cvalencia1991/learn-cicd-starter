package auth

import (
  "net/http"
  "testing"
  "errors"
)

func TestGetAPIKey(t *testing.T) {
  tests := []struct {
    name        string
    headers     http.Header
    expectedKey string
    expectErr   error
  }{
    {
      name:        "Valid API Key",
      headers:     http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
      expectedKey: "my-secret-key",
      expectErr:   nil,
    },
    {
      name:        "No Authorization Header",
      headers:     http.Header{},
      expectedKey: "",
      expectErr:   ErrNoAuthHeaderIncluded,
    },
    {
      name:        "Malformed Authorization Header",
      headers:     http.Header{"Authorization": []string{"Bearer my-secret-key"}},
      expectedKey: "",
      expectErr:   errors.New("malformed authorization header"),
    },
    {
      name:        "Missing API Key",
      headers:     http.Header{"Authorization": []string{"ApiKey"}},
      expectedKey: "",
      expectErr:   errors.New("malformed authorization header"),
    },
  }

  for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
      key, err := GetAPIKey(tt.headers)
      if key != tt.expectedKey {
        t.Errorf("expected key %q, got %q", tt.expectedKey, key)
      }
      if err != nil && tt.expectErr == nil || err == nil && tt.expectErr != nil || (err != nil && tt.expectErr != nil && err.Error() != tt.expectErr.Error()) {
        t.Errorf("expected error %v, got %v", tt.expectErr, err)
      }
    })
  }
}

