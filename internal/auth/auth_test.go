package auth

import (
    "errors"
    "net/http"
    "testing"
)

func TestGetAPIKey(t *testing.T) {
    testCases := []struct {
        name             string
        headers          http.Header
        expectedAPIKey   string
        expectedErr      error
    }{
        {
            name:           "No authorization header",
            headers:        http.Header{},
            expectedAPIKey: "",
            expectedErr:    ErrNoAuthHeaderIncluded,
        },
        {
            name: "Malformed authorization header - missing ApiKey prefix",
            headers: func() http.Header {
                h := http.Header{}
                // No "ApiKey" prefix
                h.Set("Authorization", "Bearer somevalue")
                return h
            }(),
            expectedAPIKey: "",
            expectedErr:    errors.New("malformed authorization header"),
        },
        {
            name: "Malformed authorization header - missing value",
            headers: func() http.Header {
                h := http.Header{}
                // "ApiKey" but no value after it
                h.Set("Authorization", "ApiKey")
                return h
            }(),
            expectedAPIKey: "",
            expectedErr:    errors.New("malformed authorization header"),
        },
        {
            name: "Valid authorization header",
            headers: func() http.Header {
                h := http.Header{}
                h.Set("Authorization", "ApiKey my-secret-key")
                return h
            }(),
            expectedAPIKey: "my-secret-key",
            expectedErr:    nil,
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            gotAPIKey, gotErr := GetAPIKey(tc.headers)

            if gotAPIKey != tc.expectedAPIKey {
                t.Errorf("expected API key %q, got %q", tc.expectedAPIKey, gotAPIKey)
            }

            // Compare error text. If both expected and got are non-nil, compare messages.
            // Otherwise, check for exact nil match.
            if tc.expectedErr == nil && gotErr != nil {
                t.Errorf("expected no error, got %v", gotErr)
            } else if tc.expectedErr != nil && gotErr == nil {
                t.Errorf("expected error %v, got nil", tc.expectedErr)
            } else if tc.expectedErr != nil && gotErr != nil && tc.expectedErr.Error() != gotErr.Error() {
                t.Errorf("expected error %q, got %q", tc.expectedErr.Error(), gotErr.Error())
            }
        })
    }
}

