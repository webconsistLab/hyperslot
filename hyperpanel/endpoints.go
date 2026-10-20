package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Endpoint Cache (Lazy Load)
// ═══════════════════════════════════════════════════════════════
//
// Extractor-এর /runtime endpoint থেকে data লোড করে:
//   - key → path          (endpoints map)
//   - key → HTTP method   (methods map)   ★★★ NEW ★★★
//
// Load হয় on-demand:
//   - cache খালি হলে
//   - cache stale (default 5 মিনিট) হলে
//
// Startup-এ কিছুই load হয় না।

const (
	endpointCacheTTL  = 5 * time.Minute
	endpointServerURL = "http://127.0.0.1:1111/runtime" // ★★★ /runtime (method সহ) ★★★
	apiBaseURL        = "https://api.ivacbd.com/iams/api/v1"
)

type EndpointCache struct {
	mu        sync.RWMutex
	endpoints map[string]string // key → path
	methods   map[string]string // ★★★ NEW — key → HTTP method ★★★
	loadedAt  time.Time
	loadMu    sync.Mutex
}

var endpointCache = &EndpointCache{
	endpoints: make(map[string]string),
	methods:   make(map[string]string),
}

// ═══════════════════════════════════════════════════════════════
// ensureLoaded — cache খালি বা stale হলে load করে
// ═══════════════════════════════════════════════════════════════

func (c *EndpointCache) ensureLoaded() error {
	// First check (fast path)
	c.mu.RLock()
	isEmpty := len(c.endpoints) == 0
	isStale := !c.loadedAt.IsZero() && time.Since(c.loadedAt) > endpointCacheTTL
	c.mu.RUnlock()

	if !isEmpty && !isStale {
		return nil
	}

	// Serialize load
	c.loadMu.Lock()
	defer c.loadMu.Unlock()

	// Double-check after acquiring lock
	c.mu.RLock()
	isEmpty = len(c.endpoints) == 0
	isStale = !c.loadedAt.IsZero() && time.Since(c.loadedAt) > endpointCacheTTL
	c.mu.RUnlock()

	if !isEmpty && !isStale {
		return nil
	}

	return c.load()
}

// ═══════════════════════════════════════════════════════════════
// load — endpoint server থেকে data fetch করে
// ═══════════════════════════════════════════════════════════════

func (c *EndpointCache) load() error {
	log.Printf("[ENDPOINTS] Loading from %s ...", endpointServerURL)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(endpointServerURL)
	if err != nil {
		return fmt.Errorf("endpoint server unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("endpoint server returned %d: %s", resp.StatusCode, string(body))
	}

	// ★★★ /runtime response parse — endpoints + endpoint_methods ★★★
	var runtimeData struct {
		Endpoints       map[string]string `json:"endpoints"`
		EndpointMethods map[string]string `json:"endpoint_methods"` // ★★★ NEW ★★★
		BaseURL         string            `json:"baseURL"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&runtimeData); err != nil {
		return fmt.Errorf("failed to decode JSON: %w", err)
	}

	if len(runtimeData.Endpoints) == 0 {
		return fmt.Errorf("endpoint server returned empty map")
	}

	// methods nil হলে empty map
	methods := runtimeData.EndpointMethods
	if methods == nil {
		methods = make(map[string]string)
	}

	c.mu.Lock()
	c.endpoints = runtimeData.Endpoints
	c.methods = methods // ★★★ NEW ★★★
	c.loadedAt = time.Now()
	c.mu.Unlock()

	log.Printf("[ENDPOINTS] ✅ Loaded %d endpoints, %d methods",
		len(runtimeData.Endpoints), len(methods))
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Get — key → path
// ═══════════════════════════════════════════════════════════════

func (c *EndpointCache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	path, ok := c.endpoints[key]
	if !ok {
		return "", false
	}
	// leading slash normalize
	if !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "http") {
		path = "/" + path
	}
	return path, true
}

// ═══════════════════════════════════════════════════════════════
// ★★★ NEW — GetMethod — key → HTTP method ★★★
// ═══════════════════════════════════════════════════════════════
//
// Return empty string if not found (caller fallback ব্যবহার করবে)।

func (c *EndpointCache) GetMethod(key string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.methods == nil {
		return ""
	}
	return c.methods[key]
}

// ═══════════════════════════════════════════════════════════════
// All — সব endpoint-এর copy (debug-এর জন্য)
// ═══════════════════════════════════════════════════════════════

func (c *EndpointCache) All() map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]string, len(c.endpoints))
	for k, v := range c.endpoints {
		out[k] = v
	}
	return out
}

// ═══════════════════════════════════════════════════════════════
// ★★★ NEW — AllMethods — সব methods (debug-এর জন্য) ★★★
// ═══════════════════════════════════════════════════════════════

func (c *EndpointCache) AllMethods() map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]string, len(c.methods))
	for k, v := range c.methods {
		out[k] = v
	}
	return out
}

// ═══════════════════════════════════════════════════════════════
// Has — cache খালি কিনা
// ═══════════════════════════════════════════════════════════════

func (c *EndpointCache) Has() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.endpoints) > 0
}

// ═══════════════════════════════════════════════════════════════
// BuildFullURL — path → full URL
// ═══════════════════════════════════════════════════════════════

func (c *EndpointCache) BuildFullURL(path string) string {
	if strings.HasPrefix(path, "http") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return apiBaseURL + path
}

// ═══════════════════════════════════════════════════════════════
// ForceRefresh — ম্যানুয়ালি refresh (debug / API handler-এর জন্য)
// ═══════════════════════════════════════════════════════════════

func (c *EndpointCache) ForceRefresh() error {
	c.loadMu.Lock()
	defer c.loadMu.Unlock()
	return c.load()
}
