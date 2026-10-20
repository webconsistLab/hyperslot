package captcha

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
)

type Config struct {
	Secret  string `json:"secret"`
	StartAt int    `json:"startAt"`
	Length  int    `json:"length"`
	Version int    `json:"version"`
}

type RuntimeInfo struct {
	Config           Config `json:"config"`
	BaseURL          string `json:"baseURL"`
	TurnstileSiteKey string `json:"turnstileSiteKey"`
	Environment      string `json:"environment"`
}

// ⚠️ মূল fix: পুরো captcha config object-টা একটা block হিসেবে ধরুন
// Deobfuscated ফাইলে এটা এরকম দেখতে:
//
//	const u = {
//	  secret: "AGHgA|2sIk7WlW*lQL(~QORzYpoRb#a?GMNmG.4yOq9CrC+rWR-#WUXfEvuXh&g@",
//	  startAt: Number("6"),
//	  length: Number("25"),
//	  version: Number("5")
//	};
//
// অথবা (beautify করার পর):
//
//	const u = {
//	  secret: "...",
//	  startAt: Number("6"),
//	  length: Number("25"),
//	  version: Number("5")
//	};
var reCaptchaBlock = regexp.MustCompile(`(?s)secret\s*:\s*"([^"]+)"\s*,\s*startAt\s*:\s*Number\(\s*"?(\d+)"?\s*\)\s*,\s*length\s*:\s*Number\(\s*"?(\d+)"?\s*\)\s*,\s*version\s*:\s*Number\(\s*"?(\d+)"?\s*\)`)

// Fallback: newline/space-insensitive, order અલગ હોઈ পারে
var reCaptchaBlockLoose = regexp.MustCompile(`(?s)secret\s*:\s*"([^"]+)"`)

var reNumberField = func(field string) *regexp.Regexp {
	// startAt: Number("6")  OR  startAt: 6  OR  startAt: Number(6)
	return regexp.MustCompile(`\b` + field + `\s*:\s*(?:Number\(\s*)?"?(\d+)"?\s*\)?`)
}

var reBaseURL = regexp.MustCompile(`"(https?://[a-z0-9\-\.]+/iams/api/v\d+)"`)
var reSiteKey = regexp.MustCompile(`"(0x4[A-Za-z0-9_\-]{10,})"`)
var reEnv = regexp.MustCompile(`return\s+"(production|uat|staging|development)"`)

func ParseFromFile(path string) (*RuntimeInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return Parse(string(data))
}

func Parse(src string) (*RuntimeInfo, error) {
	info := &RuntimeInfo{}

	// ── Try strict block first (secret,startAt,length,version একসাথে)
	if m := reCaptchaBlock.FindStringSubmatch(src); m != nil {
		info.Config.Secret = m[1]
		info.Config.StartAt, _ = strconv.Atoi(m[2])
		info.Config.Length, _ = strconv.Atoi(m[3])
		info.Config.Version, _ = strconv.Atoi(m[4])
	} else {
		// ── Fallback: শুধু secret খুঁজে, তারপর সেই secret থেকে nearby version বের করি
		loc := reCaptchaBlockLoose.FindStringSubmatchIndex(src)
		if loc == nil {
			return nil, fmt.Errorf("captcha secret not found")
		}
		info.Config.Secret = src[loc[2]:loc[3]]

		// secret-এর পরের 2000 char window-এ startAt/length/version খুঁজি
		start := loc[1]
		end := start + 2000
		if end > len(src) {
			end = len(src)
		}
		window := src[start:end]

		if m := reNumberField("startAt").FindStringSubmatch(window); m != nil {
			info.Config.StartAt, _ = strconv.Atoi(m[1])
		}
		if m := reNumberField("length").FindStringSubmatch(window); m != nil {
			info.Config.Length, _ = strconv.Atoi(m[1])
		}
		if m := reNumberField("version").FindStringSubmatch(window); m != nil {
			info.Config.Version, _ = strconv.Atoi(m[1])
		}
	}

	// ── baseURL / siteKey / env (এগুলো independent)
	if m := reBaseURL.FindStringSubmatch(src); m != nil {
		info.BaseURL = m[1]
	}
	if m := reSiteKey.FindStringSubmatch(src); m != nil {
		info.TurnstileSiteKey = m[1]
	}
	envMatches := reEnv.FindAllStringSubmatch(src, -1)
	if len(envMatches) > 0 {
		priority := map[string]int{"production": 4, "uat": 3, "staging": 2, "development": 1}
		best := ""
		for _, m := range envMatches {
			if priority[m[1]] > priority[best] {
				best = m[1]
			}
		}
		info.Environment = best
	}

	// ── validation
	if info.Config.Secret == "" {
		return nil, fmt.Errorf("secret not found in deobfuscated file")
	}
	// version 1..10 সীমার বাইরে হলে config আসল না — rejection করি
	if info.Config.Version < 1 || info.Config.Version > 10 {
		return nil, fmt.Errorf("version %d out of range [1..10] (regex likely caught React version — check captcha block)", info.Config.Version)
	}
	if info.Config.StartAt < 0 {
		info.Config.StartAt = 0
	}
	if info.Config.Length <= 0 {
		info.Config.Length = 25
	}
	if info.Environment == "" {
		info.Environment = "production"
	}
	return info, nil
}

func TruncateSecret(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:6] + "…" + s[len(s)-4:]
}

func DefaultBaseURL(env string) string {
	switch env {
	case "production", "prod":
		return "https://api.ivacbd.com/iams/api/v1"
	case "uat", "staging":
		return "https://api-uat-ivacbd.dgi-rnd.com/iams/api/v1"
	case "development", "dev":
		return "https://api-dev-ivacbd-v2.dgi-rnd.com/iams/api/v1"
	}
	return "https://api-dev-ivacbd.dgi-rnd.com/iams/api/v1"
}
