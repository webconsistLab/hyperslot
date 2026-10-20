package extractor

import "regexp"

// ─────────────────────────────────────────────
// String literal → path extractor
// ─────────────────────────────────────────────
//
// JS file-এ path দুভাবে থাকতে পারে:
//   1. leading slash সহ:  "/auth/v4-sign_in"
//   2. leading slash ছাড়া: "payment/<uuid>/dg-epay/initiate"
//      (ternary / config object-এর ভেতরে, obfuscator-এ সাধারণত এভাবেই থাকে)
//
// তাই regex-এ দুটো case-ই ধরতে হবে, কিন্তু "dg-epay" বা "ssl" এর মতো
// bare literal যেন ঢুকে না পড়ে — সেজন্য prefix-aware দ্বিতীয় alternative রাখা হয়েছে।

var pathRe = regexp.MustCompile(
	`"` +
		`(?:` +
		`/[a-zA-Z][a-zA-Z0-9_\-/{}.$]*` + // "/auth/signup" ধরনের
		`|` +
		`(?:auth|otp|payment|appointment|slots|invoice|file|profile|` +
		`forgot[\-_]password|high[\-_]commissions)/` + // "payment/..." ধরনের
		`[a-zA-Z0-9_\-/{}.$]*` +
		`)` +
		`(?:\?[^"]*)?` +
		`"`,
)

// ─────────────────────────────────────────────
// HTTP Method Extractor regexes
// ─────────────────────────────────────────────
//
// JS-এ multiple patterns-এ API call হয়:
//
//   1. Direct axios style:
//        lp.post("/auth/v4-sign_in", ...)
//        lp.get("/file/...", ...)
//        lp.put("/...", ...)
//        lp.delete("/...", ...)
//
//   2. Config object (method-first):
//        lp({method: "POST", url: "/auth/...", ...})
//
//   3. Config object (url-first):
//        lp({url: "/auth/...", method: "POST", ...})
//
//   4. Fetch style:
//        fetch("/auth/...", {method: "POST", ...})

var (
	// Pattern 1: .post("path") / .get("path") / .put / .delete / .patch
	methodDotRe = regexp.MustCompile(
		`(?i)\.(get|post|put|delete|patch|head|options)\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`,
	)

	// Pattern 2: method: "POST", ... url: "/auth/..."
	methodFirstRe = regexp.MustCompile(
		`(?i)method\s*:\s*["'` + "`" + `](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["'` + "`" + `][^}]{0,200}?url\s*:\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`,
	)

	// Pattern 3: url: "/auth/...", ... method: "POST"
	urlFirstRe = regexp.MustCompile(
		`(?i)url\s*:\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `][^}]{0,200}?method\s*:\s*["'` + "`" + `](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["'` + "`" + `]`,
	)

	// Pattern 4: fetch("path", {method: "POST"})
	fetchMethodRe = regexp.MustCompile(
		`(?i)fetch\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `][^)]{0,200}?method\s*:\s*["'` + "`" + `](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["'` + "`" + `]`,
	)
)

// ─────────────────────────────────────────────
// Security Header Extractor (x-sec-*)
// ─────────────────────────────────────────────
//
// Pattern: "x-sec-<name>": "<value>"
//
// Examples in JS:
//   "x-sec-navigation-state": "80d51dc5-af20-46fa-a7bb-e6a8f3f80065"
//   'x-sec-runtime-state': 'v1.5a4c8831.9a53.47ed.b579.042a2c0cee5a'

var secHeaderRe = regexp.MustCompile(
	`(?i)` + // case-insensitive
		`["']` + // opening quote
		`(x-sec-[a-z0-9\-_]+)` + // header name (capture 1)
		`["']` + // closing quote of name
		`\s*:\s*` + // colon separator
		`["']` + // opening quote of value
		`([^"']{8,})` + // value: 8+ chars, no quote (capture 2)
		`["']`, // closing quote of value
)

// ─────────────────────────────────────────────
// ★★★ NEW — Custom x-* Header Extractor ★★★
// ─────────────────────────────────────────────
//
// JS-এ যেসব header আছে যা x-sec-* নয়, কিন্তু প্রয়োজনীয়:
//
//   "x-v-request-meta": "windos.s"
//   "x-app-version": "1.0.3"
//   'x-client-id': 'abc123def456'
//   "x-device-id": "xyz789"
//
// Pattern: "x-<name>": "<value>" (যেকোনো x- prefix)
//
// Note: secHeaderRe প্রথমে check হবে — x-sec-* priority পাবে।
// এটা সব x-* ধরবে কিন্তু merge-এর সময় x-sec-* override করবে না।

var customHeaderRe = regexp.MustCompile(
	`(?i)` + // case-insensitive
		`["']` + // opening quote
		`(x-[a-z][a-z0-9\-_]+)` + // header name: x-<anything> (capture 1)
		`["']` + // closing quote
		`\s*:\s*` + // colon separator
		`["']` + // opening quote of value
		`([^"']{1,512})` + // value: 1-512 chars (capture 2)
		`["']`, // closing quote of value
)

// ─────────────────────────────────────────────
// Known endpoint keys
// ─────────────────────────────────────────────

// KnownKeys — hyper panel-এ এই নামেই endpoint access করা হবে।
var KnownKeys = []string{
	// auth
	"signin",

	// otp
	"otp_verify_signin",

	// file
	"file_upload",
	"file_overview",
	"file_slot_status",
	// appointment
	"booking_config",
	"appointment_booking_config",
	"appointment",
	"reserve_slot",
	// payment
	"payment_dg_epay_initiate",
}

// ─────────────────────────────────────────────
// EndpointPattern
// ─────────────────────────────────────────────

// EndpointPattern — dynamic অংশ (\d+, uuid, ...) থাকলেও match করে।
//
// ★★★ Method field ★★★
//   এই Method শুধু **fallback** হিসেবে কাজ করে। JS-এ method detect হলে
//   সেটাই ব্যবহার হবে, না হলে এই default ব্যবহার হবে।
type EndpointPattern struct {
	Key     string
	Regex   *regexp.Regexp
	Method  string // "GET", "POST", "PUT", "DELETE" — fallback
	IsConst bool
}

// EndpointPatterns — order গুরুত্বপূর্ণ নয়, তবে একই key একবারই থাকবে।
//
// নিয়ম:
//   - regex-এ '^' শুরুতে, '$' শেষে — পুরো path ম্যাচ করতে হবে।
//   - leading slash optional ('^/?') সেসব ক্ষেত্রে যেখানে JS ternary-তে
//     path সরাসরি string literal হিসেবে থাকে (payment, reserve_slot)।
var EndpointPatterns = []EndpointPattern{
	// ── auth ─────────────────────────────────
	{"signin", regexp.MustCompile(`^/auth/.*sign[\s\-_]*in.*$`), "POST", false},

	// ── otp ──────────────────────────────────
	//{"otp_verify_signin", regexp.MustCompile(`^/otp/verify[-_]?Signin[-_]?Otp$`), "POST", false},
	{"otp_verify_signin", regexp.MustCompile(`^/otp/.*verify[\s\-_]*Sign.*$`), "POST", false},

	// ── file ─────────────────────────────────
	//{"file_upload", regexp.MustCompile(`^/file/upload[\-_]file[\-_]v\d+$`), "POST", false},
	{"file_upload", regexp.MustCompile(`^/file/.*upload[\s\-_]*file.*$`), "POST", false},
	{"file_overview", regexp.MustCompile(`^/file/over[\-_]view[\-_]v\d+$`), "GET", false},
	//{"file_slot_status", regexp.MustCompile(`^/file/file[\-_]confirmation[\-_]and[\-_]slot[\-_]status$`), "GET", false},
	{"file_slot_status", regexp.MustCompile(`^/file/.*file[\s\-_]*confirmation.*$`), "GET", false},

	// ── appointment ──────────────────────────
	//{"booking_config", regexp.MustCompile(`^/appointment/get[\-_]booking[\-_]config$`), "GET", false},
	{"booking_config", regexp.MustCompile(`^/appointment/.*get[\s\-_]*booking.*$`), "GET", false},
	//{"appointment_booking_config", regexp.MustCompile(`^/appointment/appointment[\-_]booking[\-_]config$`), "POST", false},
	{"appointment_booking_config", regexp.MustCompile(`^/appointment/.*appointment[\s\-_]*booking.*$`), "POST", false},
	{"appointment", regexp.MustCompile(`^/appointment$`), "POST", true},

	// ── reserve_slot (uuid dynamic; leading slash optional) ──
	//{"reserve_slot", regexp.MustCompile(`^/?slots/[^/]+/reserve[\-_]slot$`), "POST", false},
	{"reserve_slot", regexp.MustCompile(`^/slots/.*reserve[\s\-_]*slot.*$`), "POST", false},

	// ── payment (both variants; leading slash optional) ──────
	//{"payment_dg_epay_initiate", regexp.MustCompile(`^/?payment/[^/]+/dg[\-_]epay/initiate$`), "POST", false},
	{"payment_dg_epay_initiate", regexp.MustCompile(`^/?payment/[^/]+/dg[\s\-_]epay/initiate$`), "POST", false},
}
