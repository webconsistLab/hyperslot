package main

// ═══════════════════════════════════════════════════════════════
// Local Captcha Pool — TTL-aware with atomic pair pop
// ═══════════════════════════════════════════════════════════════
//
// Role:
//   - Hyper Panel sync worker pair push করে (TTL metadata সহ)
//   - Automation flow atomic pop করে
//   - Serve করার আগে TTL check: total_age < maxServeAge
//   - Expired/stale pair auto-cleanup
//
// Endpoints:
//   POST /captcha/store          → {raw, encrypted, ttl_meta} push
//   GET  /captcha/get-encrypted  → pair pop → encrypted return
//   GET  /captcha/get-raw        → pair pop → raw return
//   GET  /captcha/get-pair       → pair pop → both return
//   GET  /health
//   GET  /stats

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

const (
	port = ":2222"

	// Serve করার আগে সর্বোচ্চ total age
	// Browser-এর TTL 120s, safety margin 20s → 100s
	maxServeAgeSeconds = 100.0

	// Cleanup frequency
	cleanupIntervalSec = 10
)

// ═══════════════════════════════════════════════════════════════
// Data Model
// ═══════════════════════════════════════════════════════════════

type TokenPair struct {
	Raw              string    `json:"raw"`
	Encrypted        string    `json:"encrypted"`
	CreatedAt        time.Time `json:"created_at"`         // local store time
	CloudCreatedAt   string    `json:"cloud_created_at"`   // cloud-এ কখন এসেছিল (ISO string)
	AgeAtStore       float64   `json:"age_at_store"`       // store করার সময় কত পুরনো
	RemainingAtStore float64   `json:"remaining_at_store"` // store করার সময় কত বাকি
}

// TotalAge — cloud-এ আসার পর থেকে এখান পর্যন্ত মোট কত পুরনো
func (p TokenPair) TotalAge() float64 {
	return p.AgeAtStore + time.Since(p.CreatedAt).Seconds()
}

// IsStale — serve করার উপযুক্ত কিনা
func (p TokenPair) IsStale() bool {
	return p.TotalAge() > maxServeAgeSeconds
}

// ═══════════════════════════════════════════════════════════════
// Pool
// ═══════════════════════════════════════════════════════════════

type Pool struct {
	mu    sync.Mutex
	items []TokenPair
	stats struct {
		Stored          int64 `json:"stored"`
		ServedEncrypted int64 `json:"served_encrypted"`
		ServedRaw       int64 `json:"served_raw"`
		ServedPair      int64 `json:"served_pair"`
		SkippedStale    int64 `json:"skipped_stale"`
		ExpiredDropped  int64 `json:"expired_dropped"`
		CurrentSize     int   `json:"current_size"`
		MaxSize         int   `json:"max_size"`
	}
}

var pool = &Pool{}

// ═══════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════

func main() {
	log.Printf("🚀 Local captcha pool on %s | max serve age=%.0fs",
		port, maxServeAgeSeconds)

	go cleanupLoop()

	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/captcha/store", storeHandler)
	http.HandleFunc("/captcha/get-encrypted", getEncryptedHandler)
	http.HandleFunc("/captcha/get-raw", getRawHandler)
	http.HandleFunc("/captcha/get-pair", getPairHandler)
	http.HandleFunc("/stats", statsHandler)

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}

// ═══════════════════════════════════════════════════════════════
// Cleanup
// ═══════════════════════════════════════════════════════════════

func cleanupLoop() {
	ticker := time.NewTicker(time.Duration(cleanupIntervalSec) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		pool.mu.Lock()
		before := len(pool.items)

		fresh := make([]TokenPair, 0, len(pool.items))
		for _, item := range pool.items {
			if !item.IsStale() {
				fresh = append(fresh, item)
			}
		}
		pool.items = fresh
		dropped := before - len(fresh)
		pool.stats.ExpiredDropped += int64(dropped)
		pool.stats.CurrentSize = len(pool.items)
		pool.mu.Unlock()

		if dropped > 0 {
			log.Printf("[LOCAL-POOL] 🧹 cleanup dropped %d stale | remaining: %d",
				dropped, len(fresh))
		}
	}
}

// ═══════════════════════════════════════════════════════════════
// GET /health
// ═══════════════════════════════════════════════════════════════

func healthHandler(w http.ResponseWriter, r *http.Request) {
	pool.mu.Lock()
	size := len(pool.items)
	var oldestAge, newestAge float64
	if size > 0 {
		oldestAge = pool.items[0].TotalAge()
		newestAge = pool.items[size-1].TotalAge()
	}
	pool.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "ok",
		"size":           size,
		"oldest_age_sec": oldestAge,
		"newest_age_sec": newestAge,
		"max_serve_age":  maxServeAgeSeconds,
		"server_time":    time.Now().UTC().Format(time.RFC3339),
	})
}

// ═══════════════════════════════════════════════════════════════
// POST /captcha/store
// body: {"raw": "...", "encrypted": "...", "cloud_created_at": "...",
//        "age_at_store": 12.5, "remaining_at_store": 107.5}
// ═══════════════════════════════════════════════════════════════

func storeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Raw              string  `json:"raw"`
		Encrypted        string  `json:"encrypted"`
		CloudCreatedAt   string  `json:"cloud_created_at,omitempty"`
		AgeAtStore       float64 `json:"age_at_store,omitempty"`
		RemainingAtStore float64 `json:"remaining_at_store,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Raw == "" || req.Encrypted == "" {
		http.Error(w, "raw and encrypted required", http.StatusBadRequest)
		return
	}

	pair := TokenPair{
		Raw:              req.Raw,
		Encrypted:        req.Encrypted,
		CreatedAt:        time.Now(),
		CloudCreatedAt:   req.CloudCreatedAt,
		AgeAtStore:       req.AgeAtStore,
		RemainingAtStore: req.RemainingAtStore,
	}

	// Store করার আগে TTL check
	if pair.IsStale() {
		pool.mu.Lock()
		pool.stats.SkippedStale++
		pool.mu.Unlock()
		log.Printf("[LOCAL-POOL] ⏭️  skip store (already stale: age=%.1fs)",
			pair.TotalAge())

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "token already stale",
			"age":     pair.TotalAge(),
		})
		return
	}

	pool.mu.Lock()
	pool.items = append(pool.items, pair)
	pool.stats.Stored++
	pool.stats.CurrentSize = len(pool.items)
	if len(pool.items) > pool.stats.MaxSize {
		pool.stats.MaxSize = len(pool.items)
	}
	size := len(pool.items)
	pool.mu.Unlock()

	log.Printf("[LOCAL-POOL] 📥 stored (age=%.1fs remaining=%.1fs) — size: %d",
		pair.AgeAtStore, pair.RemainingAtStore, size)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"queue_size": size,
	})
}

// ═══════════════════════════════════════════════════════════════
// popFreshPair — queue থেকে fresh pair বের করে (atomic, mutex-locked)
// ═══════════════════════════════════════════════════════════════
//
// Stale pair গুলো skip করে next fresh pair নেয়।
// Stale পাওয়া গেলে সেগুলো cleanup করে।
//
// Caller অবশ্যই pool.mu lock করে call করবে।

func popFreshPair() (*TokenPair, bool) {
	// First, drop all stale from front
	freshIdx := -1
	for i := range pool.items {
		if !pool.items[i].IsStale() {
			freshIdx = i
			break
		}
	}

	// সব stale হলে সব drop
	if freshIdx == -1 {
		dropped := len(pool.items)
		pool.items = pool.items[:0]
		pool.stats.ExpiredDropped += int64(dropped)
		pool.stats.CurrentSize = 0
		return nil, false
	}

	// freshIdx-এর আগের stale গুলো drop
	if freshIdx > 0 {
		pool.stats.ExpiredDropped += int64(freshIdx)
		pool.items = pool.items[freshIdx:]
	}

	// First fresh pair নাও
	item := pool.items[0]
	pool.items = pool.items[1:]
	pool.stats.CurrentSize = len(pool.items)

	return &item, true
}

// ═══════════════════════════════════════════════════════════════
// GET /captcha/get-encrypted — pair pop, encrypted return
// ═══════════════════════════════════════════════════════════════

func getEncryptedHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pool.mu.Lock()
	item, ok := popFreshPair()
	if !ok {
		pool.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "no fresh tokens available",
		})
		return
	}
	pool.stats.ServedEncrypted++
	remaining := len(pool.items)
	age := item.TotalAge()
	pool.mu.Unlock()

	log.Printf("[LOCAL-POOL] 📤 encrypted served (age=%.1fs) — remaining: %d",
		age, remaining)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"encrypted": item.Encrypted,
		"age":       age,
		"remaining": remaining,
	})
}

// ═══════════════════════════════════════════════════════════════
// GET /captcha/get-raw — pair pop, raw return
// ═══════════════════════════════════════════════════════════════

func getRawHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pool.mu.Lock()
	item, ok := popFreshPair()
	if !ok {
		pool.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "no fresh tokens available",
		})
		return
	}
	pool.stats.ServedRaw++
	remaining := len(pool.items)
	age := item.TotalAge()
	pool.mu.Unlock()

	log.Printf("[LOCAL-POOL] 📤 raw served (age=%.1fs) — remaining: %d",
		age, remaining)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"raw":       item.Raw,
		"age":       age,
		"remaining": remaining,
	})
}

// ═══════════════════════════════════════════════════════════════
// GET /captcha/get-pair — pair pop, both return
// ═══════════════════════════════════════════════════════════════

func getPairHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pool.mu.Lock()
	item, ok := popFreshPair()
	if !ok {
		pool.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "no fresh tokens available",
		})
		return
	}
	pool.stats.ServedPair++
	remaining := len(pool.items)
	age := item.TotalAge()
	pool.mu.Unlock()

	log.Printf("[LOCAL-POOL] 📤 pair served (age=%.1fs) — remaining: %d",
		age, remaining)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"raw":       item.Raw,
		"encrypted": item.Encrypted,
		"age":       age,
		"remaining": remaining,
	})
}

// ═══════════════════════════════════════════════════════════════
// GET /stats
// ═══════════════════════════════════════════════════════════════

func statsHandler(w http.ResponseWriter, r *http.Request) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pool.stats.CurrentSize = len(pool.items)

	// Age distribution
	var oldestAge, newestAge, avgAge float64
	if len(pool.items) > 0 {
		oldestAge = pool.items[0].TotalAge()
		newestAge = pool.items[len(pool.items)-1].TotalAge()
		sum := 0.0
		for _, item := range pool.items {
			sum += item.TotalAge()
		}
		avgAge = sum / float64(len(pool.items))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"stored":            pool.stats.Stored,
		"served_encrypted":  pool.stats.ServedEncrypted,
		"served_raw":        pool.stats.ServedRaw,
		"served_pair":       pool.stats.ServedPair,
		"skipped_stale":     pool.stats.SkippedStale,
		"expired_dropped":   pool.stats.ExpiredDropped,
		"current_size":      pool.stats.CurrentSize,
		"max_size":          pool.stats.MaxSize,
		"oldest_age_sec":    oldestAge,
		"newest_age_sec":    newestAge,
		"avg_age_sec":       avgAge,
		"max_serve_age_sec": maxServeAgeSeconds,
	})
}
