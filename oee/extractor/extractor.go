package extractor

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// Endpoint — এক endpoint-এর সব তথ্য
type Endpoint struct {
	Key    string // "signin", "otp_verify_phone", ...
	Path   string // matched path (query string ছাড়া)
	Method string // "GET", "POST", "PUT", "DELETE" — JS থেকে detected, না হলে pattern default
}

// Result — এক ফাইলের সব পাওয়া endpoint + security headers + custom headers
type Result struct {
	Endpoints map[string]Endpoint
	AllPaths  []string // duplicate ছাড়া সব path (sorted)

	// ★★★ path → method (JS-এ directly detected) ★★★
	// Example: {"/auth/v4-sign_in": "POST", "/file/file_confirmation-and_slot-status": "GET"}
	PathMethods map[string]string

	// ★★★ সব headers (x-sec-*, x-v-*, x-app-*, ইত্যাদি) ★★★
	// Example: {
	//   "x-sec-navigation-state": "80d51dc5-...",
	//   "x-sec-runtime-state": "v1.5a4c8831...",
	//   "x-v-request-meta": "windos.s"
	// }
	SecurityHeaders map[string]string
}

// ExtractFromFile — deobfuscate করা JS থেকে সব endpoint বের করে
func ExtractFromFile(path string) (*Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return Extract(string(data)), nil
}

// Extract — string literal গুলো স্ক্যান করে endpoint pattern ম্যাচ করে
func Extract(src string) *Result {
	paths := extractStringPaths(src)

	// ★★★ HTTP method detect (JS থেকে dynamic) ★★★
	pathMethods := extractHTTPMethods(src)

	// ★★★ সব header extract (x-sec-* priority + x-* custom merge) ★★★
	secHeaders := extractSecurityHeaders(src)
	customHeaders := extractCustomHeaders(src)

	// Custom headers কে secHeaders-এ merge
	// x-sec-* এর priority সবসময় বেশি — override হবে না
	for k, v := range customHeaders {
		if _, exists := secHeaders[k]; !exists {
			secHeaders[k] = v
		}
	}

	res := &Result{
		Endpoints:       make(map[string]Endpoint, len(EndpointPatterns)),
		AllPaths:        paths,
		PathMethods:     pathMethods,
		SecurityHeaders: secHeaders,
	}

	for _, raw := range paths {
		// query string বাদ (endpoint match-এর আগে)
		clean := raw
		if i := strings.IndexByte(clean, '?'); i >= 0 {
			clean = clean[:i]
		}
		// trailing slash বাদ
		clean = strings.TrimSuffix(clean, "/")
		if clean == "" {
			continue
		}

		for _, pat := range EndpointPatterns {
			if !pat.Regex.MatchString(clean) {
				continue
			}
			// একই key আগে থাকলে বেশি specific (দীর্ঘ) path রাখি
			if old, ok := res.Endpoints[pat.Key]; !ok || len(clean) > len(old.Path) {
				// ★★★ Method priority: JS-detected > pattern default ★★★
				method := pat.Method
				if jsMethod, ok := pathMethods[clean]; ok && jsMethod != "" {
					method = jsMethod
				}
				res.Endpoints[pat.Key] = Endpoint{
					Key:    pat.Key,
					Path:   clean,
					Method: method,
				}
			}
		}
	}
	return res
}

// extractStringPaths — pathRe-এর সাথে ম্যাচ করা সব string literal
// ফিরিয়ে দেয় (quote ছাড়া, duplicate ছাড়া, sorted)।
func extractStringPaths(src string) []string {
	matches := pathRe.FindAllString(src, -1)
	seen := make(map[string]struct{}, len(matches))
	out := make([]string, 0, len(matches))

	for _, m := range matches {
		// "..." থেকে দুই পাশের quote বাদ
		p := strings.Trim(m, `"`)
		if p == "" || p == "/" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// ═══════════════════════════════════════════════════════════════
// HTTP Method Extraction from JS
// ═══════════════════════════════════════════════════════════════
//
// JS-এ ৪টি pattern scan করে path → method map বানায়।
//
// Priority:
//   1 (highest): .post("path") / .get("path") — real call site
//   2:           fetch("path", {method: "X"})
//   3:           {method: "X", url: "path"}
//   4 (lowest):  {url: "path", method: "X"} — generic config object

// extractHTTPMethods — সব pattern scan করে path → method map বানায়
func extractHTTPMethods(src string) map[string]string {
	pathMethods := make(map[string]string)
	priorities := make(map[string]int) // lower = higher priority

	setMethod := func(path, method string, priority int) {
		path = strings.TrimSpace(path)
		method = strings.ToUpper(strings.TrimSpace(method))
		if path == "" || method == "" {
			return
		}
		if i := strings.IndexAny(path, "?#"); i >= 0 {
			path = path[:i]
		}
		path = strings.TrimSuffix(path, "/")
		if path == "" {
			return
		}

		existingPriority, exists := priorities[path]
		if !exists || priority < existingPriority {
			// New entry or higher priority → overwrite
			pathMethods[path] = method
			priorities[path] = priority
		}
		// same or lower priority → ignore
	}

	// ── Priority 1: .post("path") / .get("path") — REAL CALL SITE ──
	for _, m := range methodDotRe.FindAllStringSubmatch(src, -1) {
		if len(m) >= 3 {
			setMethod(m[2], m[1], 1)
		}
	}

	// ── Priority 2: fetch("path", {method: "X"}) ──
	for _, m := range fetchMethodRe.FindAllStringSubmatch(src, -1) {
		if len(m) >= 3 {
			setMethod(m[1], m[2], 2)
		}
	}

	// ── Priority 3: {method: "X", url: "path"} ──
	for _, m := range methodFirstRe.FindAllStringSubmatch(src, -1) {
		if len(m) >= 3 {
			setMethod(m[2], m[1], 3)
		}
	}

	// ── Priority 4 (lowest): {url: "path", method: "X"} — generic config ──
	for _, m := range urlFirstRe.FindAllStringSubmatch(src, -1) {
		if len(m) >= 3 {
			setMethod(m[1], m[2], 4)
		}
	}

	return pathMethods
}

// ═══════════════════════════════════════════════════════════════
// Security Headers Extraction (x-sec-*)
// ═══════════════════════════════════════════════════════════════
//
// JS-এ এই pattern-এ header থাকে:
//
//	headers: {
//	  "x-sec-navigation-state": "80d51dc5-af20-46fa-a7bb-e6a8f3f80065"
//	}

// extractSecurityHeaders — JS content থেকে সব x-sec-* header বের করে
func extractSecurityHeaders(src string) map[string]string {
	headers := make(map[string]string)

	matches := secHeaderRe.FindAllStringSubmatch(src, -1)
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(m[1]))
		value := strings.TrimSpace(m[2])
		if name == "" || value == "" {
			continue
		}
		// first occurrence wins
		if _, exists := headers[name]; !exists {
			headers[name] = value
		}
	}

	return headers
}

// ═══════════════════════════════════════════════════════════════
// ★★★ NEW — Custom Header Extraction (x-v-*, x-app-*, x-*) ★★★
// ═══════════════════════════════════════════════════════════════
//
// JS-এ যেসব header আছে যা x-sec-* নয়:
//
//	headers: {
//	  "x-v-request-meta": "windos.s",
//	  "x-app-version": "1.0.3"
//	}

// extractCustomHeaders — JS থেকে সব x-* header extract করে
//
// Note: x-sec-* এর জন্য secHeaderRe আগে priority পায়।
// এই function-এ সব x-* ধরবে, কিন্তু merge-এর সময় x-sec-* override করবে না।
func extractCustomHeaders(src string) map[string]string {
	headers := make(map[string]string)

	matches := customHeaderRe.FindAllStringSubmatch(src, -1)
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(m[1]))
		value := strings.TrimSpace(m[2])
		if name == "" || value == "" {
			continue
		}
		// Skip x-sec-* (এগুলো secHeaderRe handle করবে)
		if strings.HasPrefix(name, "x-sec-") {
			continue
		}
		// first occurrence wins
		if _, exists := headers[name]; !exists {
			headers[name] = value
		}
	}

	return headers
}

// ─────────────────────────────────────────────
// Helper methods
// ─────────────────────────────────────────────

// GetSecurityHeader — specific header value বের করে (case-insensitive)
func (r *Result) GetSecurityHeader(name string) (string, bool) {
	if r.SecurityHeaders == nil {
		return "", false
	}
	v, ok := r.SecurityHeaders[strings.ToLower(name)]
	return v, ok
}

// GetMethod — specific path এর method ফেরত দেয়
func (r *Result) GetMethod(path string) (string, bool) {
	if r.PathMethods == nil {
		return "", false
	}
	clean := path
	if i := strings.IndexAny(clean, "?#"); i >= 0 {
		clean = clean[:i]
	}
	clean = strings.TrimSuffix(clean, "/")
	v, ok := r.PathMethods[clean]
	return v, ok
}

// Print — সুন্দর আউটপুট
func (r *Result) Print() {
	fmt.Println("=== Extracted endpoints ===")
	keys := make([]string, 0, len(r.Endpoints))
	for k := range r.Endpoints {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		e := r.Endpoints[k]
		fmt.Printf("  %-8s %-28s %s\n", e.Method, k, e.Path)
	}

	if len(r.SecurityHeaders) > 0 {
		fmt.Println()
		fmt.Println("=== Security headers ===")
		hkeys := make([]string, 0, len(r.SecurityHeaders))
		for k := range r.SecurityHeaders {
			hkeys = append(hkeys, k)
		}
		sort.Strings(hkeys)
		for _, k := range hkeys {
			fmt.Printf("  %-28s %s\n", k, r.SecurityHeaders[k])
		}
	}

	fmt.Printf("\n=== All string-literal paths (%d) ===\n", len(r.AllPaths))
	for _, p := range r.AllPaths {
		fmt.Println(" ", p)
	}
}

// MustGet — key দিয়ে endpoint path বের করে; না থাকলে error
func (r *Result) MustGet(key string) (string, error) {
	e, ok := r.Endpoints[key]
	if !ok {
		return "", fmt.Errorf("endpoint %q not found in deobfuscated file", key)
	}
	return e.Path, nil
}

// Get — MustGet-এর non-error variant
func (r *Result) Get(key string) (string, bool) {
	e, ok := r.Endpoints[key]
	if !ok {
		return "", false
	}
	return e.Path, true
}

// GetEndpoint — key দিয়ে পূর্ণ endpoint (path + method)
func (r *Result) GetEndpoint(key string) (Endpoint, bool) {
	e, ok := r.Endpoints[key]
	return e, ok
}
