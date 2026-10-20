package main

// ═══════════════════════════════════════════════════════════════
// Extractor Watcher — NEVER-GIVE-UP Edition
// ═══════════════════════════════════════════════════════════════
//
// Background-এ extractor-এর /health poll করে।
//
// ★ FIX-1: sync.Once বাদ → mutex+bool (fail হলে reset-যোগ্য)
// ★ FIX-2: maxWait পার হলেও return করে না → চিরকাল retry
// ★ FIX-3: markExtractorReady() idempotent (mutex-protected)
// ★ FIX-4: Sync Worker-এর self-heal এর জন্য exported helper
//
// Startup order:
//   Panel আগে চালু হোক, Extractor পরে — watcher detect করবে।
//   Extractor ২ মিনিট, ১০ মিনিট, ২ ঘণ্টা দেরিতে চালু হলেও সমস্যা নেই।

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
// State
// ═══════════════════════════════════════════════════════════════

type ExtractorStatus struct {
	mu            sync.RWMutex
	Ready         bool      `json:"ready"`
	ReadyAt       time.Time `json:"ready_at,omitempty"`
	EndpointURL   string    `json:"endpoint_url"`
	LastError     string    `json:"last_error,omitempty"`
	Attempts      int       `json:"attempts"`
	AutoStarted   bool      `json:"auto_started"`
	EndpointCount int       `json:"endpoint_count,omitempty"`
}

var extractorStatus = &ExtractorStatus{
	EndpointURL: "http://127.0.0.1:1111",
}

// ═══════════════════════════════════════════════════════════════
// Ready Flag — mutex-based (sync.Once নয়!)
// ═══════════════════════════════════════════════════════════════
//
// sync.Once এর সমস্যা: একবার fail হলে আর reset হয় না।
// mutex+bool এ হলে state observable এবং predictable।

var (
	extractorReadyCh = make(chan struct{})
	extractorReadyMu sync.Mutex
	extractorIsReady bool
)

// markExtractorReady — idempotent (একাধিকবার call করলেও safe)
func markExtractorReady() {
	extractorReadyMu.Lock()
	defer extractorReadyMu.Unlock()

	if extractorIsReady {
		return // already ready
	}
	extractorIsReady = true

	extractorStatus.mu.Lock()
	extractorStatus.Ready = true
	extractorStatus.ReadyAt = time.Now()
	extractorStatus.mu.Unlock()

	close(extractorReadyCh)
	log.Printf("[EXTRACTOR] 🎉 ready signal sent to all subscribers")
}

// waitForExtractorReady — blocking (goroutine-এ চালান)
func waitForExtractorReady() {
	<-extractorReadyCh
}

// isExtractorReady — non-blocking check
func isExtractorReady() bool {
	extractorReadyMu.Lock()
	defer extractorReadyMu.Unlock()
	return extractorIsReady
}

// ═══════════════════════════════════════════════════════════════
// Background watcher — NEVER GIVES UP
// ═══════════════════════════════════════════════════════════════

func startExtractorWatcher(extractorURL string, maxWait time.Duration) {
	extractorURL = strings.TrimRight(extractorURL, "/")

	extractorStatus.mu.Lock()
	extractorStatus.EndpointURL = extractorURL
	extractorStatus.mu.Unlock()

	healthURL := extractorURL + "/health"
	log.Printf("[EXTRACTOR] watcher started: %s", healthURL)
	log.Printf("[EXTRACTOR] max-wait: %s (will NOT give up — keeps retrying forever)", maxWait)

	client := &http.Client{Timeout: 3 * time.Second}
	start := time.Now()
	lastLog := start
	maxWaitWarned := false
	attempt := 0

	for {
		// ★ maxWait পার হলে শুধু warn করি, return করি না
		if time.Since(start) > maxWait && !maxWaitWarned {
			log.Printf("[EXTRACTOR] ⚠️  max-wait %s exceeded — still retrying (no give-up)", maxWait)
			maxWaitWarned = true
		}

		attempt++

		// Poll /health
		resp, err := client.Get(healthURL)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			if resp.StatusCode == 200 {
				elapsed := time.Since(start).Seconds()
				log.Printf("[EXTRACTOR] ✅ /health OK after %.1fs (attempt %d)", elapsed, attempt)

				// Endpoint count
				count := fetchEndpointCount(extractorURL)

				extractorStatus.mu.Lock()
				extractorStatus.Attempts = attempt
				extractorStatus.EndpointCount = count
				extractorStatus.mu.Unlock()

				markExtractorReady()
				return
			}
			log.Printf("[EXTRACTOR] /health returned %d (attempt %d)", resp.StatusCode, attempt)
		} else {
			extractorStatus.mu.Lock()
			extractorStatus.LastError = err.Error()
			extractorStatus.mu.Unlock()
		}

		// প্রতি 10s progress log
		if time.Since(lastLog) >= 10*time.Second {
			log.Printf("[EXTRACTOR] ... still waiting (%.0fs, %d attempts)",
				time.Since(start).Seconds(), attempt)
			lastLog = time.Now()
		}

		time.Sleep(2 * time.Second)
	}
}

// fetchEndpointCount — /endpoints থেকে count
func fetchEndpointCount(baseURL string) int {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(baseURL + "/endpoints")
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0
	}
	var data map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return 0
	}
	return len(data)
}

// ═══════════════════════════════════════════════════════════════
// HTTP Handler — client polls status
// ═══════════════════════════════════════════════════════════════

func extractorStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	extractorStatus.mu.RLock()
	defer extractorStatus.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ready":          extractorStatus.Ready,
		"ready_at":       extractorStatus.ReadyAt,
		"endpoint_url":   extractorStatus.EndpointURL,
		"endpoint_count": extractorStatus.EndpointCount,
		"attempts":       extractorStatus.Attempts,
		"last_error":     extractorStatus.LastError,
		"auto_started":   extractorStatus.AutoStarted,
	})
}

// ═══════════════════════════════════════════════════════════════
// SSE — extractor ready notification stream
// ═══════════════════════════════════════════════════════════════

func extractorReadyStreamHandler(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Initial status
	fmt.Fprintf(w, "data: {\"ready\":%v}\n\n", isExtractorReady())
	flusher.Flush()

	// Wait for ready or client disconnect
	select {
	case <-extractorReadyCh:
		fmt.Fprintf(w, "data: {\"ready\":true,\"event\":\"ready\"}\n\n")
		flusher.Flush()
	case <-r.Context().Done():
		return
	case <-time.After(35 * time.Minute):
		fmt.Fprintf(w, "data: {\"ready\":false,\"event\":\"timeout\"}\n\n")
		flusher.Flush()
	}
}

// ═══════════════════════════════════════════════════════════════
// Auto-start — extractor ready হলে সব accounts চালু
// ═══════════════════════════════════════════════════════════════

func extractorAutoStartHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !isExtractorReady() {
		http.Error(w, "Extractor not ready", http.StatusServiceUnavailable)
		return
	}

	extractorStatus.mu.Lock()
	if extractorStatus.AutoStarted {
		extractorStatus.mu.Unlock()
		http.Error(w, "Auto-start already triggered", http.StatusConflict)
		return
	}
	extractorStatus.AutoStarted = true
	extractorStatus.mu.Unlock()

	var req struct {
		Step int `json:"step"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	storage.mu.Lock()
	ids := make([]string, len(storage.Accounts))
	for i, acc := range storage.Accounts {
		ids[i] = acc.ID
	}
	storage.mu.Unlock()

	log.Printf("[EXTRACTOR] 🚀 Auto-starting %d accounts from step %d", len(ids), req.Step)
	for _, id := range ids {
		go runAutomation(id, req.Step)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"count":   len(ids),
		"step":    req.Step,
	})
}
