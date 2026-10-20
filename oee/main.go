package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"deobfuscator/captcha"
	"deobfuscator/extractor"
	"deobfuscator/server"
)

const workDir = "./tools"

// ═══════════════════════════════════════════════════════════════
// Cloudflare-bypass UA & Accept (verified working)
// ═══════════════════════════════════════════════════════════════

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
	"AppleWebKit/537.36 (KHTML, like Gecko) " +
	"Chrome/154.0.0.0 Safari/537.36"

const htmlAccept = "text/html,application/xhtml+xml,application/xml;q=0.9," +
	"image/avif,image/webp,*/*;q=0.8"

const jsAccept = "*/*"

// ═══════════════════════════════════════════════════════════════
// Discovery tuning
// ═══════════════════════════════════════════════════════════════

const (
	probeIntervalMs         = 200
	probeTimeoutSec         = 10
	fullGetTimeoutSec       = 30
	contentHashCheckEnabled = true
	// 403-log spam কমানোর জন্য প্রতি N probe-এ একবার লগ
	forbiddenLogEveryN = 50
	// 403 state-এ কত probe পর পর full GET try করব
	fullGetRetryEveryN = 10
)

const defaultMaxWait = 0

func main() {
	var (
		source    = flag.String("source", "", "Base page URL (e.g. https://appointment.ivacbd.com) or local JS file")
		outFile   = flag.String("o", "deobf.js", "deobfuscated output path")
		listen    = flag.String("listen", "127.0.0.1:1111", "HTTP server listen address")
		serveOnly = flag.Bool("serve-only", false, "skip fetch/deobf, only serve existing deobf file")
		noServe   = flag.Bool("no-serve", false, "do not start HTTP server")
		keepInfra = flag.Bool("keep-infra", false, "keep decoder code in output")
		rawToken  = flag.String("raw-token", "", "encrypt this token and exit")
		maxWait   = flag.Duration("max-wait", defaultMaxWait, "max total wait time for JS discovery")
	)
	flag.Parse()

	src := *source
	if src == "" && flag.NArg() > 0 {
		src = flag.Arg(0)
	}

	cwd, _ := os.Getwd()
	outAbs := filepath.Join(cwd, *outFile)

	// ── Step 1: fetch + deobf
	if !*serveOnly {
		if src == "" {
			fmt.Fprintln(os.Stderr, `usage: go run . "https://appointment.ivacbd.com"`)
			os.Exit(2)
		}
		if err := prepareSource(src, outAbs, *keepInfra, *maxWait); err != nil {
			die("prepare", err)
		}
	}

	// ── Step 2: parse
	rt, enc, err := parseAll(src, outAbs)
	if err != nil {
		die("parse", err)
	}

	// ── Step 3: write runtime.json
	rtPath := filepath.Join(cwd, "runtime.json")
	if err := writeRuntime(rtPath, rt); err != nil {
		die("write runtime.json", err)
	}
	fmt.Printf("[+] wrote %s\n", rtPath)

	// ── Step 4: summary
	printSummary(rt)

	// ── Step 5: one-shot encrypt
	if *rawToken != "" {
		encToken, err := enc.Encrypt(*rawToken)
		if err != nil {
			die("encrypt", err)
		}
		fmt.Println()
		fmt.Println("=== Captcha encryption ===")
		fmt.Println("raw       :", *rawToken)
		fmt.Println("encrypted :", encToken)
		if back, err := enc.Decrypt(encToken); err == nil && back == *rawToken {
			fmt.Println("roundtrip : OK ✓")
		} else {
			fmt.Fprintln(os.Stderr, "  ! WARNING: roundtrip mismatch")
		}
		if *noServe {
			return
		}
	}

	// ── Step 6: HTTP server
	if !*noServe {
		srv := server.New(server.Config{
			Listen:    *listen,
			Encryptor: enc,
			Runtime:   rt,
			DeobfPath: outAbs,
			Source:    src,
			WorkDir:   workDir,
			KeepInfra: *keepInfra,
		})

		fmt.Println()
		fmt.Println("=== HTTP server ready ===")
		fmt.Printf("  GET  http://%s/health\n", *listen)
		fmt.Printf("  GET  http://%s/endpoints\n", *listen)
		fmt.Printf("  GET  http://%s/runtime\n", *listen)
		fmt.Printf("  POST http://%s/captcha/encrypt   body: {\"rawToken\":\"...\"}\n", *listen)
		fmt.Printf("  POST http://%s/captcha/decrypt   body: {\"encrypted\":\"...\"}\n", *listen)
		fmt.Printf("  POST http://%s/reload            (re-fetch & re-parse)\n", *listen)
		fmt.Println()

		if err := srv.Run(); err != nil && err != http.ErrServerClosed {
			die("server", err)
		}
	}
}

// ═══════════════════════════════════════════════════════════════
// HTTP client factory
// ═══════════════════════════════════════════════════════════════

func newHTTPClient(jar http.CookieJar) *http.Client {
	if jar == nil {
		jar, _ = cookiejar.New(nil)
	}
	tr := &http.Transport{
		ForceAttemptHTTP2:     true,
		DisableKeepAlives:     true,
		DisableCompression:    false,
		MaxIdleConns:          0,
		MaxIdleConnsPerHost:   0,
		IdleConnTimeout:       1 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	return &http.Client{
		Jar:       jar,
		Transport: tr,
		Timeout:   time.Duration(fullGetTimeoutSec) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			applyNoCacheHeaders(req)
			return nil
		},
	}
}

// ═══════════════════════════════════════════════════════════════
// Cache-bypass headers
// ═══════════════════════════════════════════════════════════════

func applyNoCacheHeaders(req *http.Request) {
	req.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0, s-maxage=0")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Expires", "0")

	req.Header.Set("CDN-Cache-Control", "no-store")
	req.Header.Set("Cloudflare-CDN-Cache-Control", "no-store")
	req.Header.Set("Surrogate-Control", "no-store")
	req.Header.Set("X-Cache-Force-Revalidate", "1")
	req.Header.Set("X-No-Cache", "1")
	req.Header.Set("X-Pull", "no-cache")

	req.Header.Del("If-None-Match")
	req.Header.Del("If-Modified-Since")
	req.Header.Del("If-Match")
	req.Header.Del("If-Unmodified-Since")
	req.Header.Del("If-Range")
}

func applyBrowserHeaders(req *http.Request, referer string, accept string) {
	if accept == "" {
		accept = htmlAccept
	}
	req.Header.Set("User-Agent", chromeUA)
	req.Header.Set("Accept", accept)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	applyNoCacheHeaders(req)

	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("sec-ch-ua", `"Chromium";v="154", "Google Chrome";v="154", "Not-A.Brand";v="99"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"Windows"`)
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
}

// ═══════════════════════════════════════════════════════════════
// Cache-bust helpers
// ═══════════════════════════════════════════════════════════════

func cacheBustURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set("_", strconv.FormatInt(time.Now().UnixNano(), 36))
	u.RawQuery = q.Encode()
	return u.String()
}

// resetJar — প্রতিবার ফ্রেশ jar (কোনো পুরনো কুকি বহন করবে না)
func resetJar(client *http.Client) {
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
}

// ═══════════════════════════════════════════════════════════════
// prepareSource
// ═══════════════════════════════════════════════════════════════

func prepareSource(src, outAbs string, keepInfra bool, maxWait time.Duration) error {
	isURL := strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://")

	if !isURL {
		fmt.Println("[*] deobfuscate (local):", src)
		if err := deobf(src, outAbs, keepInfra); err != nil {
			return fmt.Errorf("deobf: %w", err)
		}
		fmt.Println("[+] deobfuscated:", outAbs)
		return nil
	}

	if strings.HasSuffix(strings.ToLower(src), ".js") {
		fmt.Println("[*] source is direct JS URL, downloading...")
		return downloadAndDeobf(src, outAbs, keepInfra)
	}

	fmt.Println("[*] watching for dynamic JS URL at:", src)
	fmt.Printf("[*] probe interval: %dms | max wait: %s\n", probeIntervalMs, maxWait)

	jsURL, err := watchForJSURL(src, maxWait)
	if err != nil {
		return fmt.Errorf("discover JS URL: %w", err)
	}
	fmt.Println("[+] discovered JS URL:", jsURL)

	return downloadAndDeobf(jsURL, outAbs, keepInfra)
}

func downloadAndDeobf(jsURL, outAbs string, keepInfra bool) error {
	rawPath := outAbs + ".min.js"
	fmt.Println("[*] download:", jsURL)
	if err := fetch(jsURL, rawPath); err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if fi, err := os.Stat(rawPath); err == nil {
		fmt.Printf("[+] downloaded %d bytes\n", fi.Size())
	}
	fmt.Println("[*] deobfuscate:", rawPath)
	if err := deobf(rawPath, outAbs, keepInfra); err != nil {
		return fmt.Errorf("deobf: %w", err)
	}
	fmt.Println("[+] deobfuscated:", outAbs)
	return nil
}

// ═══════════════════════════════════════════════════════════════
// watchForJSURL — 403 → 200 transition detector + প্রতি probe-এ ফ্রেশ jar
// ═══════════════════════════════════════════════════════════════

type serverSignature struct {
	etag          string
	lastModified  string
	contentLength string
	bodyHash      uint64
	bodyBytes     int
	hasValidData  bool
}

// isBlockedErr — 403/429/503 কে "block state" হিসেবে চিহ্নিত করে
func isBlockedErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "403") ||
		strings.Contains(s, "Forbidden") ||
		strings.Contains(s, "429") ||
		strings.Contains(s, "Too Many Requests") ||
		strings.Contains(s, "503") ||
		strings.Contains(s, "Service Unavailable")
}

func watchForJSURL(pageURL string, maxWait time.Duration) (string, error) {
	jar, _ := cookiejar.New(nil)
	client := newHTTPClient(jar)

	// Warm-up origin (ফ্রেশ jar)
	if base := originOf(pageURL); base != "" {
		resetJar(client)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = doGet(ctx, client, base, nil, pageURL)
		cancel()
	}

	startTime := time.Now()
	deadline := startTime.Add(maxWait)

	ticker := time.NewTicker(time.Duration(probeIntervalMs) * time.Millisecond)
	defer ticker.Stop()

	var baseline serverSignature
	baselineSet := false
	probeCount := 0

	// 403-state tracking
	wasForbidden := false
	forbiddenProbes := 0
	blockedSince := time.Time{}

	// ── FIRST: baseline-এ সরাসরি full GET + extract ──
	fmt.Println("[*] initial full GET to extract JS URL...")
	for attempt := 1; attempt <= 3; attempt++ {
		html, err := fetchHTML(client, pageURL)
		if err != nil {
			fmt.Printf("[~] initial GET attempt %d failed: %v\n", attempt, err)
			if isBlockedErr(err) {
				wasForbidden = true
				forbiddenProbes = attempt
				blockedSince = time.Now()
				fmt.Printf("[~] server blocking (403/429/503) — entering wait loop\n")
				break
			}
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if jsURL, found := extractJSURLFromHTML(html, pageURL); found {
			elapsed := time.Since(startTime)
			fmt.Printf("[+] JS URL found on initial GET after %.2fs: %s\n",
				elapsed.Seconds(), jsURL)
			return jsURL, nil
		}
		fmt.Printf("[~] initial GET ok (%d bytes) but no JS URL found (attempt %d)\n",
			len(html), attempt)
		if debugJSDiscovery {
			_ = os.WriteFile(fmt.Sprintf("debug_page_%d.html", attempt), []byte(html), 0o644)
			fmt.Fprintf(os.Stderr, "[js-discovery] initial HTML saved to debug_page_%d.html\n", attempt)
		}
		break
	}

	for {
		select {
		case <-ticker.C:
			probeCount++

			if time.Now().After(deadline) {
				return "", fmt.Errorf("max wait %s exceeded after %d probes", maxWait, probeCount)
			}

			sig, err := probeServer(client, pageURL)

			// ── 403 / block state ──
			if err != nil {
				if isBlockedErr(err) {
					if !wasForbidden {
						fmt.Printf("[~] probe %d: %v  (server blocking, waiting for unblock...)\n",
							probeCount, err)
						blockedSince = time.Now()
					} else if forbiddenProbes%forbiddenLogEveryN == 0 || forbiddenProbes == 0 {
						blockedDur := time.Since(blockedSince).Round(time.Second)
						fmt.Printf("[~] probe %d: %v  (blocked for %s)\n",
							probeCount, err, blockedDur)
					}
					wasForbidden = true
					forbiddenProbes++
					baselineSet = false

					// ★ প্রতি N probe-এ একবার full GET try
					// (HEAD-এ 403 মানে GET-এও 403, কিন্তু GET-এ কখনো 200 আসতে পারে)
					if forbiddenProbes%fullGetRetryEveryN == 0 {
						html, ferr := fetchHTML(client, pageURL)
						if ferr == nil {
							fmt.Printf("[+] full GET succeeded after %d blocked probes (probe %d)!\n",
								forbiddenProbes, probeCount)
							wasForbidden = false
							forbiddenProbes = 0
							if jsURL, found := extractJSURLFromHTML(html, pageURL); found {
								elapsed := time.Since(startTime)
								fmt.Printf("[+] JS URL found after unblock (%.2fs total): %s\n",
									elapsed.Seconds(), jsURL)
								return jsURL, nil
							}
							fmt.Printf("[~] unblocked but no JS URL in HTML (%d bytes)\n", len(html))
							baseline = sig
							baselineSet = true
							continue
						}
					}
					continue
				}
				fmt.Printf("[~] probe %d: %v\n", probeCount, err)
				continue
			}

			// ── 200 পাওয়া গেল — transition check ──
			if wasForbidden {
				blockedDur := time.Since(blockedSince).Round(time.Millisecond)
				fmt.Printf("[+] probe %d: server unblocked (was 403 for %d probes, %s)!\n",
					probeCount, forbiddenProbes, blockedDur)
				wasForbidden = false
				forbiddenProbes = 0

				html, ferr := fetchHTML(client, pageURL)
				if ferr != nil {
					fmt.Printf("[~] unblocked but full GET failed: %v\n", ferr)
					baseline = sig
					baselineSet = true
					continue
				}
				if jsURL, found := extractJSURLFromHTML(html, pageURL); found {
					elapsed := time.Since(startTime)
					fmt.Printf("[+] JS URL found after unblock (%.2fs total): %s\n",
						elapsed.Seconds(), jsURL)
					return jsURL, nil
				}
				fmt.Printf("[~] unblocked but no JS URL in HTML (%d bytes)\n", len(html))
				if debugJSDiscovery {
					_ = os.WriteFile("debug_page.html", []byte(html), 0o644)
					fmt.Fprintln(os.Stderr, "[js-discovery] changed HTML saved to debug_page.html")
				}
				baseline = sig
				baselineSet = true
				continue
			}

			// ── স্বাভাবিক baseline / change detection ──
			if !baselineSet {
				baseline = sig
				baselineSet = true
				fmt.Printf("[*] baseline set (probe %d): etag=%q lm=%q len=%s hash=%x\n",
					probeCount, sig.etag, sig.lastModified, sig.contentLength, sig.bodyHash)
				continue
			}

			if !signatureChanged(baseline, sig) {
				continue
			}

			fmt.Printf("[+] CHANGE detected at probe %d! etag=%q len=%s\n",
				probeCount, sig.etag, sig.contentLength)

			html, err := fetchHTML(client, pageURL)
			if err != nil {
				fmt.Printf("[~] full GET after change failed: %v\n", err)
				baseline = sig
				continue
			}

			jsURL, found := extractJSURLFromHTML(html, pageURL)
			if found {
				elapsed := time.Since(startTime)
				fmt.Printf("[+] JS URL found after %.2fs (%d probes)\n",
					elapsed.Seconds(), probeCount)
				return jsURL, nil
			}

			fmt.Printf("[~] change detected but no JS URL in HTML (%d bytes)\n", len(html))
			if debugJSDiscovery {
				_ = os.WriteFile("debug_page.html", []byte(html), 0o644)
				fmt.Fprintln(os.Stderr, "[js-discovery] changed HTML saved to debug_page.html")
			}
			baseline = sig
		}
	}
}

// ═══════════════════════════════════════════════════════════════
// probeServer — ★ যেকোনো non-200 (403/405/501/429/503) → GET fallback
// ═══════════════════════════════════════════════════════════════

func probeServer(client *http.Client, pageURL string) (serverSignature, error) {
	resetJar(client) // ★ প্রতিবার ফ্রেশ jar
	busted := cacheBustURL(pageURL)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(probeTimeoutSec)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, busted, nil)
	if err != nil {
		return serverSignature{}, err
	}
	applyBrowserHeaders(req, originOf(pageURL), htmlAccept)
	applyNoCacheHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return serverSignature{}, err
	}
	defer resp.Body.Close()

	if debugJSDiscovery {
		dbg("probe resp: status=%s age=%q cf-cache=%q x-cache=%q etag=%q len=%q",
			resp.Status,
			resp.Header.Get("Age"),
			resp.Header.Get("CF-Cache-Status"),
			resp.Header.Get("X-Cache"),
			resp.Header.Get("ETag"),
			resp.Header.Get("Content-Length"))
	}

	// ★ যেকোনো non-200 → GET fallback
	// (HEAD-এ 403/405/501/429/503 সব ক্ষেত্রেই GET দিয়ে আবার চেষ্টা)
	if resp.StatusCode != http.StatusOK {
		return probeServerViaGet(client, pageURL)
	}

	sig := serverSignature{
		etag:          strings.TrimSpace(resp.Header.Get("ETag")),
		lastModified:  strings.TrimSpace(resp.Header.Get("Last-Modified")),
		contentLength: strings.TrimSpace(resp.Header.Get("Content-Length")),
	}
	if sig.etag != "" || sig.lastModified != "" || sig.contentLength != "" {
		sig.hasValidData = true
		return sig, nil
	}
	// HEAD 200 পেলেও empty signature → GET দিয়ে full body + signature
	return probeServerViaGet(client, pageURL)
}

func probeServerViaGet(client *http.Client, pageURL string) (serverSignature, error) {
	resetJar(client) // ★ প্রতিবার ফ্রেশ jar
	busted := cacheBustURL(pageURL)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(fullGetTimeoutSec)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, busted, nil)
	if err != nil {
		return serverSignature{}, err
	}
	applyBrowserHeaders(req, originOf(pageURL), htmlAccept)
	applyNoCacheHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return serverSignature{}, err
	}
	defer resp.Body.Close()

	if debugJSDiscovery {
		dbg("probeViaGet: status=%s age=%q cf-cache=%q x-cache=%q",
			resp.Status,
			resp.Header.Get("Age"),
			resp.Header.Get("CF-Cache-Status"),
			resp.Header.Get("X-Cache"))
	}

	if resp.StatusCode != http.StatusOK {
		return serverSignature{}, fmt.Errorf("GET %s -> %s", pageURL, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return serverSignature{}, err
	}

	sig := serverSignature{
		etag:          strings.TrimSpace(resp.Header.Get("ETag")),
		lastModified:  strings.TrimSpace(resp.Header.Get("Last-Modified")),
		contentLength: strings.TrimSpace(resp.Header.Get("Content-Length")),
		bodyBytes:     len(body),
		hasValidData:  true,
	}
	if contentHashCheckEnabled {
		sig.bodyHash = fnv64a(body)
	}
	return sig, nil
}

func signatureChanged(base, cur serverSignature) bool {
	if base.etag != "" && cur.etag != "" && base.etag != cur.etag {
		return true
	}
	if base.lastModified != "" && cur.lastModified != "" && base.lastModified != cur.lastModified {
		return true
	}
	if base.contentLength != "" && cur.contentLength != "" && base.contentLength != cur.contentLength {
		return true
	}
	if contentHashCheckEnabled && base.bodyHash != 0 && cur.bodyHash != 0 && base.bodyHash != cur.bodyHash {
		return true
	}
	return false
}

func fnv64a(data []byte) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	hash := uint64(offset64)
	for _, b := range data {
		hash ^= uint64(b)
		hash *= prime64
	}
	return hash
}

// fetchHTML — page HTML (full GET, ফ্রেশ jar, cache-bypass)
func fetchHTML(client *http.Client, pageURL string) (string, error) {
	resetJar(client) // ★ প্রতিবার ফ্রেশ jar
	busted := cacheBustURL(pageURL)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(fullGetTimeoutSec)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, busted, nil)
	if err != nil {
		return "", err
	}
	applyBrowserHeaders(req, originOf(pageURL), htmlAccept)
	applyNoCacheHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if debugJSDiscovery {
		dbg("fetchHTML: status=%s age=%q cf-cache=%q x-cache=%q len=%q",
			resp.Status,
			resp.Header.Get("Age"),
			resp.Header.Get("CF-Cache-Status"),
			resp.Header.Get("X-Cache"),
			resp.Header.Get("Content-Length"))
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s -> %s", pageURL, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// ═══════════════════════════════════════════════════════════════
// extractJSURLFromHTML (অপরিবর্তিত)
// ═══════════════════════════════════════════════════════════════

var (
	scriptOpenTagRe = regexp.MustCompile(`(?is)<script\b([^>]*)>`)
	srcValueRe      = regexp.MustCompile(`(?i)\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	typeValueRe     = regexp.MustCompile(`(?i)\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)

	linkOpenTagRe = regexp.MustCompile(`(?is)<link\b([^>]*)>`)
	hrefValueRe   = regexp.MustCompile(`(?i)\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	relValueRe    = regexp.MustCompile(`(?i)\brel\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	asValueRe     = regexp.MustCompile(`(?i)\bas\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)

	headSectionRe = regexp.MustCompile(`(?is)<head\b[^>]*>(.*?)</head>`)

	hashedJSRe = regexp.MustCompile(
		`(?i)^[A-Za-z0-9_\.\-]*[-.][A-Za-z0-9_]{6,}\.js$`,
	)
)

var vendorJSPatterns = []string{
	"react", "react-dom", "vue", "angular", "jquery",
	"polyfill", "vendor", "chunk-vendors", "runtime",
	"lodash", "moment", "axios", "bootstrap",
	"cloudflare", "beacon", "analytics", "gtag", "ga.js",
	"sentry", "hotjar", "segment", "intercom", "crisp",
	"recaptcha", "turnstile", "hcaptcha", "googletagmanager",
	"google-analytics", "facebook", "fb.", "tiktok",
}

var debugJSDiscovery = os.Getenv("DEOBF_DEBUG") == "1"

func dbg(format string, args ...any) {
	if debugJSDiscovery {
		fmt.Fprintf(os.Stderr, "[js-discovery] "+format+"\n", args...)
	}
}

type jsCandidate struct {
	raw        string
	inHead     bool
	isModule   bool
	isVendor   bool
	isAsset    bool
	isHashed   bool
	isMainName bool
}

func extractJSURLFromHTML(html, pageURL string) (string, bool) {
	headHTML := html
	bodyHTML := ""
	if m := headSectionRe.FindStringSubmatchIndex(html); m != nil && len(m) >= 4 {
		headHTML = html[m[2]:m[3]]
		bodyHTML = html[:m[0]] + html[m[1]:]
	} else {
		low := strings.ToLower(html)
		if i := strings.Index(low, "</head>"); i > 0 {
			headHTML = html[:i]
			bodyHTML = html[i:]
		} else if i := strings.Index(low, "<body"); i > 0 {
			headHTML = html[:i]
			bodyHTML = html[i:]
		}
	}

	baseOrigin := originOf(pageURL)
	var candidates []jsCandidate

	collectScripts := func(fragment string, inHead bool) {
		for _, m := range scriptOpenTagRe.FindAllStringSubmatch(fragment, -1) {
			if len(m) < 2 {
				continue
			}
			attrs := m[1]

			sm := srcValueRe.FindStringSubmatch(attrs)
			if sm == nil {
				continue
			}
			raw := strings.TrimSpace(firstNonEmpty(sm[1], sm[2], sm[3]))
			if raw == "" {
				continue
			}
			if i := strings.IndexAny(raw, "?#"); i >= 0 {
				raw = raw[:i]
			}
			if !strings.HasSuffix(strings.ToLower(raw), ".js") {
				continue
			}

			isModule := false
			if tm := typeValueRe.FindStringSubmatch(attrs); tm != nil {
				if strings.EqualFold(strings.TrimSpace(firstNonEmpty(tm[1], tm[2], tm[3])), "module") {
					isModule = true
				}
			}

			candidates = append(candidates, makeJSCandidate(raw, inHead, isModule))
		}
	}

	collectScripts(headHTML, true)
	if bodyHTML != "" {
		collectScripts(bodyHTML, false)
	}

	for _, m := range linkOpenTagRe.FindAllStringSubmatch(html, -1) {
		if len(m) < 2 {
			continue
		}
		attrs := m[1]

		rel := ""
		if rm := relValueRe.FindStringSubmatch(attrs); rm != nil {
			rel = strings.ToLower(strings.TrimSpace(firstNonEmpty(rm[1], rm[2], rm[3])))
		}
		as := ""
		if am := asValueRe.FindStringSubmatch(attrs); am != nil {
			as = strings.ToLower(strings.TrimSpace(firstNonEmpty(am[1], am[2], am[3])))
		}
		if rel != "modulepreload" && !(rel == "preload" && as == "script") {
			continue
		}

		hm := hrefValueRe.FindStringSubmatch(attrs)
		if hm == nil {
			continue
		}
		raw := strings.TrimSpace(firstNonEmpty(hm[1], hm[2], hm[3]))
		if i := strings.IndexAny(raw, "?#"); i >= 0 {
			raw = raw[:i]
		}
		if !strings.HasSuffix(strings.ToLower(raw), ".js") {
			continue
		}
		candidates = append(candidates, makeJSCandidate(raw, true, true))
	}

	dbg("pageURL=%s htmlLen=%d headLen=%d candidates=%d",
		pageURL, len(html), len(headHTML), len(candidates))
	for i, c := range candidates {
		dbg("  cand[%d] raw=%q head=%v module=%v vendor=%v asset=%v hashed=%v main=%v",
			i, c.raw, c.inHead, c.isModule, c.isVendor, c.isAsset, c.isHashed, c.isMainName)
	}

	if len(candidates) == 0 {
		dbg("no .js candidates found")
		return "", false
	}

	pick := func(fn func(jsCandidate) bool) (string, bool) {
		for _, c := range candidates {
			if fn(c) {
				full := normalizeToFullURL(c.raw, baseOrigin)
				dbg("picked: %s", full)
				return full, true
			}
		}
		return "", false
	}

	if u, ok := pick(func(c jsCandidate) bool {
		return c.inHead && c.isAsset && c.isHashed && !c.isVendor
	}); ok {
		return u, true
	}
	if u, ok := pick(func(c jsCandidate) bool {
		return c.inHead && c.isModule && c.isAsset && !c.isVendor
	}); ok {
		return u, true
	}
	if u, ok := pick(func(c jsCandidate) bool {
		return c.inHead && c.isMainName && !c.isVendor
	}); ok {
		return u, true
	}
	if u, ok := pick(func(c jsCandidate) bool {
		return c.inHead && c.isAsset && !c.isVendor
	}); ok {
		return u, true
	}
	if u, ok := pick(func(c jsCandidate) bool {
		return c.inHead && c.isHashed && !c.isVendor
	}); ok {
		return u, true
	}
	if u, ok := pick(func(c jsCandidate) bool {
		return c.inHead && !c.isVendor
	}); ok {
		return u, true
	}
	if u, ok := pick(func(c jsCandidate) bool {
		return c.isModule && c.isAsset && !c.isVendor
	}); ok {
		return u, true
	}
	if u, ok := pick(func(c jsCandidate) bool {
		return c.isAsset && !c.isVendor
	}); ok {
		return u, true
	}
	if u, ok := pick(func(c jsCandidate) bool {
		return c.isHashed && !c.isVendor
	}); ok {
		return u, true
	}
	if u, ok := pick(func(c jsCandidate) bool {
		return !c.isVendor
	}); ok {
		return u, true
	}
	if u, ok := pick(func(c jsCandidate) bool { return true }); ok {
		return u, true
	}
	return "", false
}

func makeJSCandidate(raw string, inHead, isModule bool) jsCandidate {
	low := strings.ToLower(raw)

	isVendor := false
	for _, v := range vendorJSPatterns {
		if strings.Contains(low, v) {
			isVendor = true
			break
		}
	}

	base := raw
	if i := strings.LastIndex(raw, "/"); i >= 0 {
		base = raw[i+1:]
	}

	baseLow := strings.ToLower(base)
	isMainName := false
	for _, n := range []string{"index", "app", "main", "bundle"} {
		if strings.HasPrefix(baseLow, n+".") ||
			strings.HasPrefix(baseLow, n+"-") ||
			strings.HasPrefix(baseLow, n+"_") {
			isMainName = true
			break
		}
	}

	return jsCandidate{
		raw:      raw,
		inHead:   inHead,
		isModule: isModule,
		isVendor: isVendor,
		isAsset: strings.Contains(low, "/assets/") ||
			strings.Contains(low, "/static/") ||
			strings.Contains(low, "/build/") ||
			strings.Contains(low, "/dist/"),
		isHashed:   hashedJSRe.MatchString(base),
		isMainName: isMainName,
	}
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func normalizeToFullURL(raw, baseOrigin string) string {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	if strings.HasPrefix(raw, "//") {
		return "https:" + raw
	}
	if strings.HasPrefix(raw, "/") {
		return strings.TrimRight(baseOrigin, "/") + raw
	}
	return strings.TrimRight(baseOrigin, "/") + "/" + raw
}

// ═══════════════════════════════════════════════════════════════
// parseAll (অপরিবর্তিত)
// ═══════════════════════════════════════════════════════════════

func parseAll(src, deobfPath string) (*server.Runtime, *captcha.Encryptor, error) {
	res, err := extractor.ExtractFromFile(deobfPath)
	if err != nil {
		return nil, nil, fmt.Errorf("extract endpoints: %w", err)
	}

	rtInfo, err := captcha.ParseFromFile(deobfPath)
	if err != nil {
		return nil, nil, fmt.Errorf("captcha config: %w", err)
	}

	enc, err := captcha.NewEncryptorFromJS(deobfPath, rtInfo.Config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!] JS extractor failed, falling back to pure-Go:", err)
		enc, err = captcha.NewEncryptor(rtInfo)
		if err != nil {
			return nil, nil, fmt.Errorf("encryptor: %w", err)
		}
	} else {
		fmt.Println("[+] captcha: using JS runtime (goja)")
	}

	if err := enc.SanityCheck("0123456789abcdefghij"); err != nil {
		fmt.Fprintln(os.Stderr, "[!] sanity check failed:", err)
	}

	epMap := make(map[string]string, len(res.Endpoints))
	epMethodMap := make(map[string]string, len(res.Endpoints))
	for k, v := range res.Endpoints {
		epMap[k] = v.Path
		epMethodMap[k] = v.Method
	}

	rt := &server.Runtime{
		Source:          src,
		GeneratedAt:     time.Now().UTC(),
		BaseURL:         rtInfo.BaseURL,
		SiteKey:         rtInfo.TurnstileSiteKey,
		Environment:     rtInfo.Environment,
		Captcha:         rtInfo.Config,
		Endpoints:       epMap,
		EndpointMethods: epMethodMap,
		RawPaths:        res.AllPaths,
		SecurityHeaders: res.SecurityHeaders,
	}

	if len(res.SecurityHeaders) > 0 {
		fmt.Println()
		fmt.Println("=== Security headers extracted ===")
		for k, v := range res.SecurityHeaders {
			fmt.Printf("  %-30s %s\n", k, v)
		}
	} else {
		fmt.Println()
		fmt.Println("[!] WARNING: no x-sec-* security headers found in JS")
	}

	fmt.Println()
	fmt.Println("=== Endpoint methods (from JS) ===")
	for k, v := range res.Endpoints {
		fmt.Printf("  %-8s %-28s %s\n", v.Method, k, v.Path)
	}

	return rt, enc, nil
}

// ═══════════════════════════════════════════════════════════════
// Runtime IO (অপরিবর্তিত)
// ═══════════════════════════════════════════════════════════════

func writeRuntime(path string, rt *server.Runtime) error {
	b, err := json.MarshalIndent(rt, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func printSummary(rt *server.Runtime) {
	fmt.Println()
	fmt.Println("=== Extracted endpoints ===")
	wanted := []string{
		"signin", "signup", "otp_signup",
		"otp_verify_phone", "otp_verify_email", "otp_verify_signin",
		"booking_config", "appointment_booking_config",
		"file_slot_status", "reserve_slot",
		"payment_dg_epay_initiate", "payment_ssl_initiate",
		"invoice_all_by_user", "profile",
	}
	for _, k := range wanted {
		if p, ok := rt.Endpoints[k]; ok {
			method := ""
			if rt.EndpointMethods != nil {
				method = rt.EndpointMethods[k]
			}
			if method == "" {
				method = "POST"
			}
			fmt.Printf("  %-6s %-30s %s\n", method, k, p)
		}
	}

	fmt.Println()
	fmt.Println("=== Captcha config ===")
	fmt.Println("environment :", rt.Environment)
	fmt.Println("baseURL     :", rt.BaseURL)
	fmt.Println("siteKey     :", rt.SiteKey)
	fmt.Println("secret      :", captcha.TruncateSecret(rt.Captcha.Secret))
	fmt.Println("startAt     :", rt.Captcha.StartAt)
	fmt.Println("length      :", rt.Captcha.Length)
	fmt.Println("version     :", rt.Captcha.Version, "->", captcha.VersionName(rt.Captcha.Version))
}

// ═══════════════════════════════════════════════════════════════
// HTTP download helpers (অপরিবর্তিত)
// ═══════════════════════════════════════════════════════════════

func fetch(rawURL, dst string) error {
	jar, _ := cookiejar.New(nil)
	client := newHTTPClient(jar)
	client.Timeout = 90 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if base := originOf(rawURL); base != "" {
		_ = doGet(ctx, client, base, nil, rawURL)
	}

	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := doGet(ctx, client, rawURL, f, rawURL); err != nil {
		return err
	}

	fi, _ := f.Stat()
	if fi.Size() < 1024 {
		return fmt.Errorf("file too small (%d bytes)", fi.Size())
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	head := make([]byte, 64)
	_, _ = f.Read(head)
	head = bytes.TrimSpace(head)
	if bytes.HasPrefix(head, []byte("<!DOCTYPE")) ||
		bytes.HasPrefix(head, []byte("<html")) {
		return fmt.Errorf("downloaded content is HTML, not JS")
	}
	return nil
}

func originOf(full string) string {
	u, err := url.Parse(full)
	if err != nil || u.Scheme == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/"
}

func doGet(ctx context.Context, c *http.Client, rawURL string, w io.Writer, refererForJS string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}

	isJS := strings.HasSuffix(strings.ToLower(rawURL), ".js")
	accept := htmlAccept
	if isJS {
		accept = jsAccept
	}
	referer := originOf(rawURL)
	if refererForJS != "" && refererForJS != rawURL {
		referer = refererForJS
	}
	applyBrowserHeaders(req, referer, accept)
	applyNoCacheHeaders(req)

	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s -> %s", rawURL, resp.Status)
	}
	if w != nil {
		_, err = io.Copy(w, resp.Body)
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// ═══════════════════════════════════════════════════════════════
// Deobfuscate helper (অপরিবর্তিত)
// ═══════════════════════════════════════════════════════════════

func deobf(in, out string, keepInfra bool) error {
	abs, err := filepath.Abs(workDir)
	if err != nil {
		return err
	}
	inAbs, _ := filepath.Abs(in)
	outAbs, _ := filepath.Abs(out)

	args := []string{
		filepath.Join(abs, "deobfuscator.js"),
		inAbs, "-o", outAbs,
		"--strings", outAbs + ".strings.txt",
		"-q",
	}
	if keepInfra {
		args = append(args, "--keep-infra")
	}

	cmd := exec.Command("node", args...)
	cmd.Dir = abs
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w\n%s", err, stderr.String())
	}
	return nil
}

func die(what string, err error) {
	fmt.Fprintf(os.Stderr, "[!] %s: %v\n", what, err)
	os.Exit(1)
}
