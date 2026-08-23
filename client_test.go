package approval

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCheckSubmit_APISuccess(t *testing.T) {
	server := mockApprovalAPI(t, CheckSubmitResponse{
		CanSubmit:          true,
		HasSubmitterConfig: true,
	}, http.StatusOK)
	defer server.Close()

	client := NewClient(server.URL, "test-secret")
	pageId := uuid.New()
	orgIds := []uuid.UUID{uuid.New()}
	userOrgId := uuid.New()

	result := client.CheckSubmit(pageId, orgIds, userOrgId)
	if !result.CanSubmit {
		t.Fatal("expected canSubmit=true")
	}
	if !result.HasSubmitterConfig {
		t.Fatal("expected hasSubmitterConfig=true")
	}
	if result.Source != "api" {
		t.Fatalf("expected source=api, got %s", result.Source)
	}
}

func TestCheckSubmit_CacheHit(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(CheckSubmitResponse{
			CanSubmit:          true,
			HasSubmitterConfig: true,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-secret")
	pageId := uuid.New()
	orgIds := []uuid.UUID{uuid.New()}
	userOrgId := uuid.New()

	// First call hits API
	result1 := client.CheckSubmit(pageId, orgIds, userOrgId)
	if result1.Source != "api" {
		t.Fatalf("expected source=api, got %s", result1.Source)
	}

	// Second call should hit cache
	result2 := client.CheckSubmit(pageId, orgIds, userOrgId)
	if result2.Source != "cache" {
		t.Fatalf("expected source=cache, got %s", result2.Source)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 API call, got %d", callCount)
	}
}

func TestCheckSubmit_APIError_DegradedFallback(t *testing.T) {
	client := NewClient("http://localhost:9999", "test-secret") // unreachable
	pageId := uuid.New()
	orgIds := []uuid.UUID{uuid.New()}
	userOrgId := uuid.New()

	result := client.CheckSubmit(pageId, orgIds, userOrgId)
	if result.HasSubmitterConfig {
		t.Fatal("expected hasSubmitterConfig=false in degraded mode")
	}
	if result.Source != "degraded" {
		t.Fatalf("expected source=degraded, got %s", result.Source)
	}
}

func TestCheckSubmit_StaleCacheServedOnAPIFailure(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(CheckSubmitResponse{
			CanSubmit:          true,
			HasSubmitterConfig: true,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-secret")
	// Set very short TTL so cache becomes stale immediately
	client.cacheTTL = 1 * time.Millisecond

	pageId := uuid.New()
	orgIds := []uuid.UUID{uuid.New()}
	userOrgId := uuid.New()

	// First call hits API and caches
	result1 := client.CheckSubmit(pageId, orgIds, userOrgId)
	if result1.Source != "api" {
		t.Fatalf("expected source=api, got %s", result1.Source)
	}

	// Wait for cache to become stale
	time.Sleep(10 * time.Millisecond)

	// Point client to unreachable server
	client.baseURL = "http://localhost:9999"

	// Should serve stale cache
	result2 := client.CheckSubmit(pageId, orgIds, userOrgId)
	if result2.Source != "stale-cache" {
		t.Fatalf("expected source=stale-cache, got %s", result2.Source)
	}
	if !result2.CanSubmit {
		t.Fatal("expected canSubmit=true from stale cache")
	}
}

func TestCheckSubmit_NoSubmitterConfig(t *testing.T) {
	server := mockApprovalAPI(t, CheckSubmitResponse{
		CanSubmit:          false,
		HasSubmitterConfig: false,
	}, http.StatusOK)
	defer server.Close()

	client := NewClient(server.URL, "test-secret")
	result := client.CheckSubmit(uuid.New(), []uuid.UUID{uuid.New()}, uuid.New())
	if result.HasSubmitterConfig {
		t.Fatal("expected hasSubmitterConfig=false")
	}
	if result.Source != "api" {
		t.Fatalf("expected source=api, got %s", result.Source)
	}
}

func TestCheckSubmit_HMACSignature(t *testing.T) {
	var receivedSig, receivedTs string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-Gateway-Signature")
		receivedTs = r.Header.Get("X-Gateway-Timestamp")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(CheckSubmitResponse{})
	}))
	defer server.Close()

	client := NewClient(server.URL, "my-secret-key")
	client.CheckSubmit(uuid.New(), []uuid.UUID{uuid.New()}, uuid.New())

	if receivedSig == "" {
		t.Fatal("expected X-Gateway-Signature header to be set")
	}
	if receivedTs == "" {
		t.Fatal("expected X-Gateway-Timestamp header to be set")
	}
}

func TestCacheKeyFor(t *testing.T) {
	pageId := uuid.New()
	userOrgId := uuid.New()
	org1 := uuid.New()
	org2 := uuid.New()

	// Same inputs → same key
	key1 := cacheKeyFor(pageId, []uuid.UUID{org1, org2}, userOrgId)
	key2 := cacheKeyFor(pageId, []uuid.UUID{org1, org2}, userOrgId)
	if key1 != key2 {
		t.Fatal("same inputs should produce same cache key")
	}

	// Different orgIds → different key
	key3 := cacheKeyFor(pageId, []uuid.UUID{org1}, userOrgId)
	if key1 == key3 {
		t.Fatal("different orgIds should produce different cache key")
	}

	// Different userOrgId → different key
	key4 := cacheKeyFor(pageId, []uuid.UUID{org1, org2}, uuid.New())
	if key1 == key4 {
		t.Fatal("different userOrgId should produce different cache key")
	}
}

func mockApprovalAPI(t *testing.T, response CheckSubmitResponse, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(response)
	}))
}

func TestBuildTLSConfig_NoCerts(t *testing.T) {
	// Clear env vars to ensure clean state
	os.Unsetenv("MTLS_ENABLED")
	os.Unsetenv("MTLS_CA_CERT_PATH")
	os.Unsetenv("MTLS_CERT_PATH")
	os.Unsetenv("MTLS_KEY_PATH")

	// When MTLS_ENABLED is not set, NewClient should not configure TLS
	client := NewClient("http://localhost:9999", "secret")
	// Just verify it doesn't panic and client is created
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestBuildTLSConfig_MissingPaths(t *testing.T) {
	t.Setenv("MTLS_ENABLED", "true")
	t.Setenv("MTLS_CA_CERT_PATH", "")
	t.Setenv("MTLS_CERT_PATH", "")
	t.Setenv("MTLS_KEY_PATH", "")

	// Should not panic — just skip TLS config
	client := NewClient("http://localhost:9999", "secret")
	if client == nil {
		t.Fatal("expected non-nil client even with missing cert paths")
	}
}
