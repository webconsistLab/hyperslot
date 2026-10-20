package main

// ═══════════════════════════════════════════════════════════════
// Captcha Sync Worker — SELF-HEALING Edition
// ═══════════════════════════════════════════════════════════════
//
// Panel startup-এ immediate চালু (auto all-এর অপেক্ষা না)।
//
// ★ FIX: Self-healing — Extractor Watcher fail হলেও Sync Worker
//         নিজে /health probe করে ready detect করবে।
//
// Flow:
//   1. isExtractorReady() check → false হলে selfHealExtractorReady()
//   2. Cloud থেকে raw token + timestamp pull
//   3. TTL check:
//      - age > maxTokenAge (60s) → drop
//      - remaining < minRemaining (30s) → drop
//      - অন্যথায় → encrypt (:1111/captcha/encrypt)
//   4. Local pool-এ {raw, encrypted, ttl_meta} store
//   5. Encrypt fail হলে raw cloud-এ requeue

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// Config
// ═══════════════════════════════════════════════════════════════

var (
	captchaCloudURL = "https://solved-captcha-358970714333.asia-south1.run.app"
	hyperPanelURL   = "http://127.0.0.1:1111"
	localPoolURL    = "http://127.0.0.1:2222"
	syncClient      = &http.Client{Timeout: 15 * time.Second}
)

const (
	// কত সেকেন্ড পুরনো token encrypt করা হবে
	maxTokenAgeSeconds = 60.0

	// TTL শেষ হওয়ার কত সেকেন্ড আগে পর্যন্ত encrypt
	minRemainingSeconds = 30.0

	// প্রতি cycle-এ কত token pull
	syncBatchSize = 10

	// Ticker interval
	syncTickSeconds = 1
)

// ═══════════════════════════════════════════════════════════════
// Stats
// ═══════════════════════════════════════════════════════════════

var syncStats struct {
	Cycles        atomic.Int64
	SkippedNoEnc  atomic.Int64
	SelfHealCount atomic.Int64 // ★ NEW — কতবার self-heal হয়েছে
	Fetched       atomic.Int64
	Encrypted     atomic.Int64
	Stored        atomic.Int64
	EncryptFails  atomic.Int64
	StoreFails    atomic.Int64
	NoTokens      atomic.Int64
	StaleDropped  atomic.Int64
	AgeSum        atomic.Int64 // ×100 for precision
}

// ═══════════════════════════════════════════════════════════════
// TokenMeta
// ═══════════════════════════════════════════════════════════════

type TokenMeta struct {
	CreatedAt        string  `json:"created_at"`
	ExpiresAt        string  `json:"expires_at"`
	AgeSeconds       float64 `json:"age_seconds"`
	RemainingSeconds float64 `json:"remaining_seconds"`
}

// ═══════════════════════════════════════════════════════════════
// startCaptchaSync — main loop
// ═══════════════════════════════════════════════════════════════

func startCaptchaSync() {
	log.Printf("[SYNC] captcha sync worker started")
	log.Printf("[SYNC]   cloud:       %s", captchaCloudURL)
	log.Printf("[SYNC]   encrypt:     %s", hyperPanelURL)
	log.Printf("[SYNC]   pool:        %s", localPoolURL)
	log.Printf("[SYNC]   max age:     %.0fs", maxTokenAgeSeconds)
	log.Printf("[SYNC]   min remain:  %.0fs", minRemainingSeconds)
	log.Printf("[SYNC]   self-heal:   enabled")

	ticker := time.NewTicker(time.Duration(syncTickSeconds) * time.Second)
	defer ticker.Stop()

	cycleCounter := 0
	lastSkipLog := time.Time{}
	selfHealPending := false // ★ first time self-heal attempt

	for range ticker.C {
		cycleCounter++
		syncStats.Cycles.Add(1)

		// ★★★ Check extractor ready (with self-healing fallback) ★★★
		if !isExtractorReady() {
			// Self-heal: watcher fail করলেও নিজে detect করি
			if selfHealExtractorReady() {
				// self-heal সফল
				syncStats.SelfHealCount.Add(1)
				log.Printf("[SYNC] 🔧 self-healed! Extractor detected by worker (watcher may have failed)")
				selfHealPending = false
			} else {
				// এখনো ready না
				syncStats.SkippedNoEnc.Add(1)

				// প্রতি 30s log
				if time.Since(lastSkipLog) >= 30*time.Second {
					log.Printf("[SYNC] ⏸  extractor not ready yet (skipped %d cycles, still probing)",
						syncStats.SkippedNoEnc.Load())
					lastSkipLog = time.Now()

					// ★ প্রথম বার self-heal চেষ্টা হলে জানাই
					if !selfHealPending {
						log.Printf("[SYNC] 💡 self-heal active: worker নিজে probe করছে")
						selfHealPending = true
					}
				}
				continue
			}
		}

		// Batch pull
		for i := 0; i < syncBatchSize; i++ {
			if !syncOne() {
				break
			}
		}
	}
}

// ═══════════════════════════════════════════════════════════════
// selfHealExtractorReady — Worker-এর নিজস্ব rescue mechanism
// ═══════════════════════════════════════════════════════════════
//
// Extractor Watcher কোনোভাবে fail করলে (max-wait, panic, ইত্যাদি),
// Sync Worker নিজে /health probe করে ready mark করবে।

func selfHealExtractorReady() bool {
	probeURL := hyperPanelURL + "/health"
	client := &http.Client{Timeout: 3 * time.Second}

	resp, err := client.Get(probeURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != 200 {
		return false
	}

	// Extractor reachable → manually ready mark করি
	// (markExtractorReady idempotent, তাই নিরাপদ)
	markExtractorReady()
	return true
}

// ═══════════════════════════════════════════════════════════════
// syncOne — single token sync
// ═══════════════════════════════════════════════════════════════

func syncOne() bool {
	// Cloud pull
	rawToken, meta, err := cloudGetRaw()
	if err != nil {
		if err.Error() == "empty" {
			syncStats.NoTokens.Add(1)
			return false
		}
		log.Printf("[SYNC] cloud error: %v", err)
		return false
	}
	syncStats.Fetched.Add(1)
	syncStats.AgeSum.Add(int64(meta.AgeSeconds * 100))

	log.Printf("[SYNC] 📥 raw from cloud (len=%d age=%.1fs remaining=%.1fs)",
		len(rawToken), meta.AgeSeconds, meta.RemainingSeconds)

	// TTL check 1: too old
	if meta.AgeSeconds > maxTokenAgeSeconds {
		syncStats.StaleDropped.Add(1)
		log.Printf("[SYNC] 🗑️  too old (age=%.1fs > %.1fs) — dropping",
			meta.AgeSeconds, maxTokenAgeSeconds)
		return true
	}

	// TTL check 2: expiring soon
	if meta.RemainingSeconds < minRemainingSeconds {
		syncStats.StaleDropped.Add(1)
		log.Printf("[SYNC] 🗑️  expiring soon (%.1fs remaining < %.1fs) — dropping",
			meta.RemainingSeconds, minRemainingSeconds)
		return true
	}

	// Encrypt
	encrypted, err := hyperPanelEncrypt(rawToken)
	if err != nil {
		syncStats.EncryptFails.Add(1)
		log.Printf("[SYNC] ❌ encrypt failed: %v — requeueing", err)

		if pushErr := cloudPushRaw(rawToken); pushErr != nil {
			log.Printf("[SYNC] ❌❌ requeue failed: %v — TOKEN LOST", pushErr)
		} else {
			log.Printf("[SYNC] ♻️  requeued to cloud")
		}
		return false
	}
	syncStats.Encrypted.Add(1)

	// Local store
	if err := localPoolStore(rawToken, encrypted, meta); err != nil {
		syncStats.StoreFails.Add(1)
		log.Printf("[SYNC] ❌ store failed: %v", err)
		_ = cloudPushRaw(rawToken)
		return true
	}
	syncStats.Stored.Add(1)
	log.Printf("[SYNC] ✅ stored (enc_len=%d age=%.1fs)",
		len(encrypted), meta.AgeSeconds)
	return true
}

// ═══════════════════════════════════════════════════════════════
// Cloud helpers
// ═══════════════════════════════════════════════════════════════

func cloudGetRaw() (string, *TokenMeta, error) {
	req, _ := http.NewRequest("GET", captchaCloudURL+"/captcha/get-raw", nil)
	resp, err := syncClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return "", nil, fmt.Errorf("empty")
	}
	if resp.StatusCode != 200 {
		return "", nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var result struct {
		Success          bool    `json:"success"`
		Raw              string  `json:"raw"`
		CreatedAt        string  `json:"created_at"`
		ExpiresAt        string  `json:"expires_at"`
		AgeSeconds       float64 `json:"age_seconds"`
		RemainingSeconds float64 `json:"remaining_seconds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", nil, fmt.Errorf("decode: %w", err)
	}
	if !result.Success || result.Raw == "" {
		return "", nil, fmt.Errorf("empty")
	}

	meta := &TokenMeta{
		CreatedAt:        result.CreatedAt,
		ExpiresAt:        result.ExpiresAt,
		AgeSeconds:       result.AgeSeconds,
		RemainingSeconds: result.RemainingSeconds,
	}
	return result.Raw, meta, nil
}

func cloudPushRaw(raw string) error {
	body, _ := json.Marshal(map[string]string{
		"raw_token": raw,
		"source":    "sync-worker-requeue",
	})

	resp, err := syncClient.Post(captchaCloudURL+"/captcha/solved",
		"application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("cloud push %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Hyper Panel encrypt
// ═══════════════════════════════════════════════════════════════

func hyperPanelEncrypt(raw string) (string, error) {
	body, _ := json.Marshal(map[string]string{"rawToken": raw})

	resp, err := syncClient.Post(hyperPanelURL+"/captcha/encrypt",
		"application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("hyper-panel %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Encrypted string `json:"encrypted"`
		Success   bool   `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.Encrypted == "" {
		return "", fmt.Errorf("empty encrypted")
	}
	return result.Encrypted, nil
}

// ═══════════════════════════════════════════════════════════════
// Local pool store
// ═══════════════════════════════════════════════════════════════

func localPoolStore(raw, encrypted string, meta *TokenMeta) error {
	body, _ := json.Marshal(map[string]interface{}{
		"raw":                raw,
		"encrypted":          encrypted,
		"cloud_created_at":   meta.CreatedAt,
		"age_at_store":       meta.AgeSeconds,
		"remaining_at_store": meta.RemainingSeconds,
	})

	resp, err := syncClient.Post(localPoolURL+"/captcha/store",
		"application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("local pool %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Debug endpoint
// ═══════════════════════════════════════════════════════════════

func captchaSyncStatsHandler(w http.ResponseWriter, r *http.Request) {
	poolSize, poolStats := fetchLocalPoolStats()

	avgAge := 0.0
	if syncStats.Fetched.Load() > 0 {
		avgAge = float64(syncStats.AgeSum.Load()) / 100.0 / float64(syncStats.Fetched.Load())
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"cycles":          syncStats.Cycles.Load(),
		"skipped_no_enc":  syncStats.SkippedNoEnc.Load(),
		"self_heal_count": syncStats.SelfHealCount.Load(), // ★ NEW
		"fetched":         syncStats.Fetched.Load(),
		"encrypted":       syncStats.Encrypted.Load(),
		"stored":          syncStats.Stored.Load(),
		"encrypt_fails":   syncStats.EncryptFails.Load(),
		"store_fails":     syncStats.StoreFails.Load(),
		"no_tokens":       syncStats.NoTokens.Load(),
		"stale_dropped":   syncStats.StaleDropped.Load(),
		"avg_token_age":   avgAge,
		"local_pool_size": poolSize,
		"local_pool":      poolStats,
		"cloud_url":       captchaCloudURL,
		"local_pool_url":  localPoolURL,
		"encrypt_ready":   isExtractorReady(),
		"max_age_sec":     maxTokenAgeSeconds,
		"min_remain_sec":  minRemainingSeconds,
	})
}

func fetchLocalPoolStats() (int, map[string]interface{}) {
	resp, err := syncClient.Get(localPoolURL + "/stats")
	if err != nil {
		return -1, nil
	}
	defer resp.Body.Close()

	var stats map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return -1, nil
	}
	size := 0
	if s, ok := stats["current_size"].(float64); ok {
		size = int(s)
	}
	return size, stats
}

// ═══════════════════════════════════════════════════════════════
// localPoolFetch — automation এখান থেকে token নেয়
// ═══════════════════════════════════════════════════════════════

func localPoolFetch(ctx context.Context, path, field, ip string) (string, error) {
	urlStr := localPoolURL + path
	headers := map[string]string{"User-Agent": "Mozilla/5.0"}

	retryCount := getTokenRetryCount()
	retryDelay := getTokenRetryDelay()
	if retryCount < 1 {
		retryCount = 60
	}
	if retryDelay < 1 {
		retryDelay = 3
	}

	totalWait := time.Duration(retryCount*retryDelay) * time.Second
	log.Printf("[LOCAL-POOL] fetching %q | max %d × %ds = %s",
		field, retryCount, retryDelay, totalWait)

	start := time.Now()

	for attempt := 1; attempt <= retryCount; attempt++ {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		resp, err := doRequestWithRetry(ctx, "GET", urlStr, nil, headers, ip, 1)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode == 200 {
				var result map[string]interface{}
				if err := json.Unmarshal(body, &result); err == nil {
					if v, ok := result[field].(string); ok && v != "" {
						log.Printf("[LOCAL-POOL] ✅ got %q after %.1fs (attempt %d/%d)",
							field, time.Since(start).Seconds(), attempt, retryCount)
						return v, nil
					}
				}
				return "", fmt.Errorf("field %q empty", field)
			}

			if resp.StatusCode == 404 {
				if attempt%5 == 0 || attempt == 1 {
					log.Printf("[LOCAL-POOL] ⏳ empty (attempt %d/%d, %.1fs)",
						attempt, retryCount, time.Since(start).Seconds())
				}
			} else {
				log.Printf("[LOCAL-POOL] status %d (attempt %d/%d)",
					resp.StatusCode, attempt, retryCount)
			}
		} else {
			log.Printf("[LOCAL-POOL] error (attempt %d/%d): %v",
				attempt, retryCount, err)
		}

		if attempt < retryCount {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(retryDelay) * time.Second):
			}
		}
	}

	return "", fmt.Errorf("no %q token after %d attempts (%.0fs)",
		field, retryCount, time.Since(start).Seconds())
}
