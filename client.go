// Package approval provides an HTTP client for service-to-service calls
// to bbo-approval-api's check-submit endpoint.
//
// Design:
//   - Primary: call approval-api via HTTP for submitter authorization check
//   - Cache: 5-minute TTL with stale-while-revalidate (serve stale if API down)
//   - Fallback: if approval-api is unreachable, fall back to local logic
//     via gotypes.CheckSubmitterAccessLevels (requires caller to provide
//     the user's access level ID and the strategy's submitter access levels)
//
// This ensures zero-downtime: if approval-api restarts, services can still
// serve check-submit requests from cache or local fallback.
package approval

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/natifdevelopment/go-circuitbreaker"
	gotypes "github.com/natifdevelopment/go-types"
)

// CheckSubmitRequest is the request body sent to approval-api.
type CheckSubmitRequest struct {
	PageId    uuid.UUID   `json:"pageId"`
	OrgIds    []uuid.UUID `json:"orgIds"`
	UserOrgId uuid.UUID   `json:"userOrgId"`
}

// CheckSubmitResponse is the response from approval-api.
type CheckSubmitResponse struct {
	CanSubmit          bool `json:"canSubmit"`
	HasSubmitterConfig bool `json:"hasSubmitterConfig"`
}

// cacheEntry holds a cached response with its fetch time.
type cacheEntry struct {
	response  CheckSubmitResponse
	fetchedAt time.Time
}

// Client is the HTTP client for approval-api's check-submit endpoint.
// It is safe for concurrent use.
type Client struct {
	baseURL      string
	httpClient   *http.Client
	sharedSecret string

	// cache: key = pageId+userOrgId+orgIds hash → entry
	cacheMu sync.RWMutex
	cache   map[string]cacheEntry

	// cacheTTL is how long a cached entry is considered fresh.
	// After TTL, stale entries are served only if the API is unreachable.
	cacheTTL time.Duration

	// cb is the circuit breaker for approval-api calls.
	cb *circuitbreaker.CircuitBreaker
}

// MetricsCallbacks allows external systems to observe cache and circuit
// breaker events without this package importing them directly.
type MetricsCallbacks struct {
	OnCacheHit           func()
	OnCacheMiss          func()
	OnStaleServed        func()
	OnCircuitStateChange func(oldState, newState int)
}

// metricsCallbacks holds optional callbacks for observability.
var metricsCallbacks MetricsCallbacks

// SetMetricsCallbacks registers callbacks for cache and circuit breaker events.
// Must be called before NewClient. If not set, events are not recorded.
func SetMetricsCallbacks(cb MetricsCallbacks) {
	metricsCallbacks = cb
}

// TraceInjector is a callback that injects W3C traceparent headers into
// outbound HTTP requests. This allows the caller service (which has OTel)
// to propagate trace context to approval-api without this package importing OTel.
type TraceInjector func(req *http.Request)

// traceInjector holds the optional trace header injector.
var traceInjector TraceInjector

// SetTraceInjector registers a callback that injects trace headers into
// outbound HTTP requests. Must be called before NewClient.
// If not set, trace headers are not injected (tracing context not propagated).
func SetTraceInjector(injector TraceInjector) {
	traceInjector = injector
}

// NewClient creates a new approval-api client.
// baseURL is the approval-api base URL (e.g. "http://bbo-approval-api:8090").
// sharedSecret is the GATEWAY_SHARED_SECRET for HMAC signing.
func NewClient(baseURL string, sharedSecret string) *Client {
	transport := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     30 * time.Second,
	}

	// Configure mTLS if enabled via environment variables
	if os.Getenv("MTLS_ENABLED") == "true" {
		if tlsConfig, err := buildTLSConfig(); err == nil {
			transport.TLSClientConfig = tlsConfig
		}
	}

	cb := circuitbreaker.New(circuitbreaker.DefaultConfig())
	if metricsCallbacks.OnCircuitStateChange != nil {
		cb.OnStateChange(func(oldState, newState circuitbreaker.State) {
			metricsCallbacks.OnCircuitStateChange(int(oldState), int(newState))
		})
	}

	return &Client{
		baseURL:      baseURL,
		httpClient:   &http.Client{Timeout: 5 * time.Second, Transport: transport},
		sharedSecret: sharedSecret,
		cache:        make(map[string]cacheEntry),
		cacheTTL:     5 * time.Minute,
		cb:           cb,
	}
}

// buildTLSConfig constructs a TLS config for mTLS from environment variables.
// Expects:
//
//	MTLS_CA_CERT_PATH  — path to CA certificate (PEM)
//	MTLS_CERT_PATH     — path to client certificate (PEM)
//	MTLS_KEY_PATH      — path to client private key (PEM)
func buildTLSConfig() (*tls.Config, error) {
	caCertPath := os.Getenv("MTLS_CA_CERT_PATH")
	certPath := os.Getenv("MTLS_CERT_PATH")
	keyPath := os.Getenv("MTLS_KEY_PATH")

	if caCertPath == "" || certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("mTLS enabled but cert paths not set")
	}

	// Load CA cert
	caCert, err := os.ReadFile(caCertPath) // #nosec G304 G703 -- path from env/config or caller, not request input
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	// Load client cert+key
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: false, // Verify server cert against CA
		MinVersion:         tls.VersionTLS12,
	}, nil
}

// CheckSubmitResult is the full result including whether fallback was used.
type CheckSubmitResult struct {
	CanSubmit          bool
	HasSubmitterConfig bool
	// Source indicates where the result came from: "api", "cache", or "fallback".
	Source string
}

// CheckSubmit calls approval-api to check if the user can submit approval.
//
// If approval-api is unreachable, it tries:
// 1. Serve from cache (stale-while-revalidate)
// 2. Return HasSubmitterConfig=false (caller falls back to creator/updater)
//
// This ensures the feature degrades gracefully during approval-api downtime.
func (c *Client) CheckSubmit(pageId uuid.UUID, orgIds []uuid.UUID, userOrgId uuid.UUID) CheckSubmitResult {
	cacheKey := cacheKeyFor(pageId, orgIds, userOrgId)

	// Try cache first (fresh)
	if entry, ok := c.getCacheIfFresh(cacheKey); ok {
		if metricsCallbacks.OnCacheHit != nil {
			metricsCallbacks.OnCacheHit()
		}
		return CheckSubmitResult{
			CanSubmit:          entry.response.CanSubmit,
			HasSubmitterConfig: entry.response.HasSubmitterConfig,
			Source:             "cache",
		}
	}
	if metricsCallbacks.OnCacheMiss != nil {
		metricsCallbacks.OnCacheMiss()
	}

	// Circuit breaker: skip API call if circuit is open
	if !c.cb.AllowRequest() {
		if entry, ok := c.getCacheIfStale(cacheKey); ok {
			if metricsCallbacks.OnStaleServed != nil {
				metricsCallbacks.OnStaleServed()
			}
			return CheckSubmitResult{
				CanSubmit:          entry.response.CanSubmit,
				HasSubmitterConfig: entry.response.HasSubmitterConfig,
				Source:             "stale-cache",
			}
		}
		return CheckSubmitResult{
			CanSubmit:          false,
			HasSubmitterConfig: false,
			Source:             "degraded",
		}
	}

	// Call approval-api
	resp, err := c.callAPI(pageId, orgIds, userOrgId)
	if err == nil {
		c.cb.RecordSuccess()
		c.setCache(cacheKey, *resp)
		return CheckSubmitResult{
			CanSubmit:          resp.CanSubmit,
			HasSubmitterConfig: resp.HasSubmitterConfig,
			Source:             "api",
		}
	}

	// API failed
	c.cb.RecordFailure()

	// Try stale cache
	if entry, ok := c.getCacheIfStale(cacheKey); ok {
		if metricsCallbacks.OnStaleServed != nil {
			metricsCallbacks.OnStaleServed()
		}
		return CheckSubmitResult{
			CanSubmit:          entry.response.CanSubmit,
			HasSubmitterConfig: entry.response.HasSubmitterConfig,
			Source:             "stale-cache",
		}
	}

	// No cache available — degrade gracefully
	return CheckSubmitResult{
		CanSubmit:          false,
		HasSubmitterConfig: false,
		Source:             "degraded",
	}
}

// CheckSubmitWithFallback calls approval-api and falls back to local logic
// if the API is unreachable and no cache is available.
//
// The fallback parameters (submitterAccessLevels, userAccessLevelId) allow
// the caller to perform the same check locally using gotypes.CheckSubmitterAccessLevels.
// This is useful when the caller already has the strategy loaded.
func (c *Client) CheckSubmitWithFallback(
	pageId uuid.UUID,
	orgIds []uuid.UUID,
	userOrgId uuid.UUID,
	submitterAccessLevels []gotypes.ApprovalStrategySubmitterAccessLevel,
	userAccessLevelId *uuid.UUID,
) CheckSubmitResult {
	result := c.CheckSubmit(pageId, orgIds, userOrgId)
	if result.Source != "degraded" {
		return result
	}

	// Fallback to local logic
	canSubmit := gotypes.CheckSubmitterAccessLevels(
		submitterAccessLevels,
		&userOrgId,
		userAccessLevelId,
		orgIds,
	)
	return CheckSubmitResult{
		CanSubmit:          canSubmit,
		HasSubmitterConfig: len(submitterAccessLevels) > 0,
		Source:             "fallback",
	}
}

// callAPI makes the HTTP POST to approval-api.
func (c *Client) callAPI(pageId uuid.UUID, orgIds []uuid.UUID, userOrgId uuid.UUID) (*CheckSubmitResponse, error) {
	reqBody := CheckSubmitRequest{
		PageId:    pageId,
		OrgIds:    orgIds,
		UserOrgId: userOrgId,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	endpoint := c.baseURL + "/api/v1/approval/check-submit"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Inject W3C traceparent header for distributed tracing (P6.2)
	if traceInjector != nil {
		traceInjector(req)
	}

	// Sign request with HMAC-SHA256 using GATEWAY_SHARED_SECRET
	if c.sharedSecret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		mac := hmac.New(sha256.New, []byte(c.sharedSecret))
		mac.Write([]byte(http.MethodPost + "\n" + req.URL.Path + "\n" + ts))
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Gateway-Signature", sig)
		req.Header.Set("X-Gateway-Timestamp", ts)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call approval-api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("approval-api returned %d: %s", resp.StatusCode, string(body))
	}

	var result CheckSubmitResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &result, nil
}

// --- Cache helpers ---

func cacheKeyFor(pageId uuid.UUID, orgIds []uuid.UUID, userOrgId uuid.UUID) string {
	// Simple key: pageId + userOrgId + sorted orgIds
	// For large orgIds slices, this is O(n) but n is typically <10
	key := pageId.String() + "|" + userOrgId.String()
	for _, id := range orgIds {
		key += "|" + id.String()
	}
	return key
}

func (c *Client) getCacheIfFresh(key string) (cacheEntry, bool) {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()
	entry, ok := c.cache[key]
	if !ok {
		return entry, false
	}
	if time.Since(entry.fetchedAt) > c.cacheTTL {
		return entry, false
	}
	return entry, true
}

func (c *Client) getCacheIfStale(key string) (cacheEntry, bool) {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()
	entry, ok := c.cache[key]
	return entry, ok
}

func (c *Client) setCache(key string, resp CheckSubmitResponse) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	c.cache[key] = cacheEntry{
		response:  resp,
		fetchedAt: time.Now(),
	}
}
