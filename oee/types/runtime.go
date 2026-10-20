package types

import (
	"deobfuscator/captcha"
	"time"
)

type Runtime struct {
	Source      string            `json:"source"`
	GeneratedAt time.Time         `json:"generatedAt"`
	BaseURL     string            `json:"baseURL"`
	SiteKey     string            `json:"siteKey"`
	Environment string            `json:"environment"`
	Captcha     captcha.Config    `json:"captchaConfig"`
	Endpoints   map[string]string `json:"endpoints"`
	RawPaths    []string          `json:"rawPaths,omitempty"`
}
