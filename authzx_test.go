package authzx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func mockServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

func TestCheck_Allowed(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/authorize" {
			t.Errorf("expected /v1/authorize, got %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("expected Bearer test-key, got %s", r.Header.Get("Authorization"))
		}

		var req AuthorizeRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Subject.ID != "user-1" {
			t.Errorf("expected subject ID user-1, got %s", req.Subject.ID)
		}
		if req.Action != "read" {
			t.Errorf("expected action read, got %s", req.Action)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AuthorizeResponse{
			Allowed:    true,
			Reason:     "role_match",
			PolicyID:   "pol-1",
			AccessPath: "role",
		})
	})
	defer srv.Close()

	client := NewClient("test-key", WithBaseURL(srv.URL))
	allowed, err := client.Check(context.Background(),
		Subject{ID: "user-1"},
		"read",
		Resource{ID: "doc-1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("expected allowed=true")
	}
}

func TestCheck_Denied(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AuthorizeResponse{Allowed: false, Reason: "no matching policy"})
	})
	defer srv.Close()

	client := NewClient("test-key", WithBaseURL(srv.URL))
	allowed, err := client.Check(context.Background(),
		Subject{ID: "user-1"}, "delete", Resource{ID: "doc-1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("expected allowed=false")
	}
}

func TestAuthorize_FullResponse(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AuthorizeResponse{
			Allowed:    true,
			Reason:     "direct_access",
			PolicyID:   "pol-123",
			AccessPath: "direct",
		})
	})
	defer srv.Close()

	client := NewClient("test-key", WithBaseURL(srv.URL))
	resp, err := client.Authorize(context.Background(), &AuthorizeRequest{
		Subject:  Subject{ID: "user-1", Type: "user"},
		Resource: Resource{ID: "doc-1", Type: "document"},
		Action:   "read",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Allowed {
		t.Error("expected allowed")
	}
	if resp.PolicyID != "pol-123" {
		t.Errorf("expected pol-123, got %s", resp.PolicyID)
	}
	if resp.AccessPath != "direct" {
		t.Errorf("expected direct, got %s", resp.AccessPath)
	}
}

func TestAuthorize_AuthError(t *testing.T) {
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte("invalid api key"))
	})
	defer srv.Close()

	client := NewClient("bad-key", WithBaseURL(srv.URL))
	_, err := client.Authorize(context.Background(), &AuthorizeRequest{
		Subject:  Subject{ID: "user-1"},
		Resource: Resource{ID: "doc-1"},
		Action:   "read",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsAuthError(err) {
		t.Errorf("expected auth error, got %v", err)
	}
}

func TestAuthorize_ServerError_Retries(t *testing.T) {
	attempts := 0
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(500)
			w.Write([]byte("internal error"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AuthorizeResponse{Allowed: true, Reason: "ok"})
	})
	defer srv.Close()

	client := NewClient("test-key", WithBaseURL(srv.URL), WithRetries(2))
	resp, err := client.Authorize(context.Background(), &AuthorizeRequest{
		Subject:  Subject{ID: "user-1"},
		Resource: Resource{ID: "doc-1"},
		Action:   "read",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Allowed {
		t.Error("expected allowed after retry")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestAuthorize_NoRetryOn4xx(t *testing.T) {
	attempts := 0
	srv := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(400)
		w.Write([]byte("bad request"))
	})
	defer srv.Close()

	client := NewClient("test-key", WithBaseURL(srv.URL))
	_, err := client.Authorize(context.Background(), &AuthorizeRequest{
		Subject:  Subject{ID: "user-1"},
		Resource: Resource{ID: "doc-1"},
		Action:   "read",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt (no retry on 4xx), got %d", attempts)
	}
}

func TestSubject_TypeOptional(t *testing.T) {
	s := Subject{ID: "user-1"}
	data, _ := json.Marshal(s)
	var m map[string]interface{}
	json.Unmarshal(data, &m)
	if _, ok := m["type"]; ok {
		t.Error("type should be omitted when empty")
	}
}
