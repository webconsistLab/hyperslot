package captcha

import (
	"fmt"
	"os"
	"sync"
)

// ─────────────────────────────────────────────
// Encryptor
// ─────────────────────────────────────────────

// Encryptor — captcha encrypt/decrypt-এর একক ইন্টারফেস।
//
// js != nil হলে JS runtime (goja) authoritative — obfuscated ফাইলের আসল
// algorithm ব্যবহার করা হয়। js == nil হলে pure-Go fallback চলে
// (version অনুযায়ী v1-v10)।
type Encryptor struct {
	mu        sync.RWMutex
	cfg       Config
	js        *jsRuntime // non-nil হলে JS-ই authoritative
	snippet   string     // ডিবাগের জন্য
	deobfPath string     // যে ফাইল থেকে snippet extract হয়েছে
}

// ─────────────────────────────────────────────
// Constructors
// ─────────────────────────────────────────────

// NewEncryptorFromJS — deobf ফাইল থেকে JS snippet extract করে encryptor বানায়।
// এটাই recommended path — algorithm / version পরিবর্তন হলে অটো adapt হবে।
func NewEncryptorFromJS(deobfPath string, cfg Config) (*Encryptor, error) {
	raw, err := os.ReadFile(deobfPath)
	if err != nil {
		return nil, fmt.Errorf("read deobf: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[captcha] NewEncryptorFromJS: version=%d startAt=%d length=%d secretLen=%d\n",
		cfg.Version, cfg.StartAt, cfg.Length, len(cfg.Secret))

	snippet, err := ExtractJSSnippetVersioned(string(raw), cfg.Version)
	if err != nil {
		return nil, fmt.Errorf("extract snippet v%d: %w", cfg.Version, err)
	}

	// ডিবাগ — snippet file-এ লিখি
	_ = os.WriteFile("captcha_snippet.js", []byte(snippet), 0o644)
	fmt.Fprintf(os.Stderr, "[captcha] snippet written: %d bytes → captcha_snippet.js\n", len(snippet))

	rt, err := newJSRuntime(snippet)
	if err != nil {
		return nil, fmt.Errorf("build JS runtime: %w", err)
	}
	return &Encryptor{
		cfg:       cfg,
		js:        rt,
		snippet:   snippet,
		deobfPath: deobfPath,
	}, nil
}

// NewEncryptor — পুরনো signature (backward compat)।
// এটা pure-Go fallback ব্যবহার করে (version অনুযায়ী)।
// নতুন কোডে NewEncryptorFromJS ব্যবহার করুন।
func NewEncryptor(info *RuntimeInfo) (*Encryptor, error) {
	if info == nil {
		return nil, fmt.Errorf("nil RuntimeInfo")
	}
	return &Encryptor{cfg: info.Config}, nil
}

// ─────────────────────────────────────────────
// Accessors
// ─────────────────────────────────────────────

// Config — কপি ফেরত দেয়
func (e *Encryptor) Config() Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg
}

// Snippet — extracted JS snippet (ডিবাগ/লগের জন্য)
func (e *Encryptor) Snippet() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.snippet
}

// DeobfPath — যে ফাইল থেকে snippet extract হয়েছে
func (e *Encryptor) DeobfPath() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.deobfPath
}

// ─────────────────────────────────────────────
// Encrypt / Decrypt
// ─────────────────────────────────────────────

// Encrypt — raw token থেকে encrypted string
func (e *Encryptor) Encrypt(raw string) (string, error) {
	if raw == "" {
		return "", ErrEmptyToken
	}

	e.mu.RLock()
	js := e.js
	cfg := e.cfg
	e.mu.RUnlock()

	// JS path — সবচেয়ে নির্ভরযোগ্য (আসল JS-এর algorithm)
	if js != nil {
		return js.encrypt(cfg.Secret, raw, cfg.StartAt, cfg.Length)
	}
	// pure-Go fallback — version অনুযায়ী সঠিক implementation
	return encryptByVersion(cfg.Version, cfg.Secret, raw, cfg.StartAt, cfg.Length)
}

// Decrypt — encrypted string থেকে raw token
func (e *Encryptor) Decrypt(enc string) (string, error) {
	if enc == "" {
		return "", ErrEmptyToken
	}

	e.mu.RLock()
	js := e.js
	cfg := e.cfg
	e.mu.RUnlock()

	if js != nil {
		return js.decrypt(cfg.Secret, enc, cfg.StartAt, cfg.Length)
	}
	return decryptByVersion(cfg.Version, cfg.Secret, enc, cfg.StartAt, cfg.Length)
}

// ─────────────────────────────────────────────
// Reload
// ─────────────────────────────────────────────

// Reload — deobf ফাইল থেকে JS snippet আবার extract করে runtime রিফ্রেশ করে।
// ফাইল পরিবর্তন হলে server-এর /reload endpoint এটা কল করে।
// deobfPath খালি হলে e.deobfPath ব্যবহার করে।
func (e *Encryptor) Reload(deobfPath string) error {
	e.mu.RLock()
	if deobfPath == "" {
		deobfPath = e.deobfPath
	}
	version := e.cfg.Version
	e.mu.RUnlock()

	if deobfPath == "" {
		return fmt.Errorf("reload: no deobf path set")
	}

	raw, err := os.ReadFile(deobfPath)
	if err != nil {
		return fmt.Errorf("reload: read %s: %w", deobfPath, err)
	}

	fmt.Fprintf(os.Stderr, "[captcha] Reload: version=%d path=%s\n", version, deobfPath)

	snippet, err := ExtractJSSnippetVersioned(string(raw), version)
	if err != nil {
		return fmt.Errorf("reload: extract snippet: %w", err)
	}
	rt, err := newJSRuntime(snippet)
	if err != nil {
		return fmt.Errorf("reload: build runtime: %w", err)
	}

	e.mu.Lock()
	e.js = rt
	e.snippet = snippet
	e.deobfPath = deobfPath
	e.mu.Unlock()

	fmt.Fprintf(os.Stderr, "[captcha] Reload OK: %d bytes snippet\n", len(snippet))
	return nil
}

// ─────────────────────────────────────────────
// SanityCheck
// ─────────────────────────────────────────────

// SanityCheck — roundtrip verify (encrypt → decrypt → same?)
func (e *Encryptor) SanityCheck(sample string) error {
	if sample == "" {
		return nil
	}
	enc, err := e.Encrypt(sample)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	back, err := e.Decrypt(enc)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	if back != sample {
		return fmt.Errorf("roundtrip mismatch: in=%q enc=%q back=%q", sample, enc, back)
	}
	return nil
}
