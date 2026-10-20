package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"deobfuscator/captcha"
	"deobfuscator/extractor"
)

// ─────────────────────────────────────────────
// Runtime — main থেকে আসা সব data
// ─────────────────────────────────────────────

type Runtime struct {
	Source      string         `json:"source"`
	GeneratedAt time.Time      `json:"generatedAt"`
	BaseURL     string         `json:"baseURL"`
	SiteKey     string         `json:"siteKey"`
	Environment string         `json:"environment"`
	Captcha     captcha.Config `json:"captchaConfig"`

	// Endpoints — key → path
	Endpoints map[string]string `json:"endpoints"`

	// ★★★ NEW — endpoint key → HTTP method (JS থেকে detected) ★★★
	// Example: {"signin": "POST", "file_slot_status": "GET"}
	EndpointMethods map[string]string `json:"endpoint_methods,omitempty"`

	RawPaths        []string          `json:"rawPaths,omitempty"`
	SecurityHeaders map[string]string `json:"security_headers,omitempty"`
}

// ─────────────────────────────────────────────
// Config & Server
// ─────────────────────────────────────────────

type Config struct {
	Listen    string
	Encryptor *captcha.Encryptor
	Runtime   *Runtime // pointer — main থেকে পাস করা
	DeobfPath string
	Source    string
	WorkDir   string
	KeepInfra bool
}

type Server struct {
	cfg  Config
	mu   sync.RWMutex
	http *http.Server
}

func New(cfg Config) *Server {
	return &Server{cfg: cfg}
}

func (s *Server) Run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/endpoints", s.handleEndpoints)
	mux.HandleFunc("/endpoint-methods", s.handleEndpointMethods) // ★★★ NEW ★★★
	mux.HandleFunc("/runtime", s.handleRuntime)
	mux.HandleFunc("/captcha/encrypt", s.handleEncrypt)
	mux.HandleFunc("/captcha/decrypt", s.handleDecrypt)
	mux.HandleFunc("/reload", s.handleReload)
	mux.HandleFunc("/security-headers", s.handleSecurityHeaders)

	s.http = &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           withCORS(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	return s.http.Serve(ln)
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.http == nil {
		return nil
	}
	return s.http.Shutdown(ctx)
}

// ─────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	writeJSON(w, 200, map[string]any{
		"ok":         true,
		"source":     s.cfg.Source,
		"deobfPath":  s.cfg.DeobfPath,
		"serverTime": time.Now().UTC(),
	})
}

func (s *Server) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg.Runtime == nil {
		writeErr(w, 500, "runtime not initialized")
		return
	}
	writeJSON(w, 200, s.cfg.Runtime.Endpoints)
}

// ★★★ NEW — endpoint key → method ★★★
//
// Response:
//
//	{
//	  "methods": {
//	    "signin": "POST",
//	    "file_slot_status": "GET",
//	    ...
//	  },
//	  "count": 8
//	}
func (s *Server) handleEndpointMethods(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg.Runtime == nil {
		writeErr(w, 500, "runtime not initialized")
		return
	}
	methods := s.cfg.Runtime.EndpointMethods
	if methods == nil {
		methods = map[string]string{}
	}
	writeJSON(w, 200, map[string]any{
		"methods": methods,
		"count":   len(methods),
	})
}

func (s *Server) handleRuntime(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg.Runtime == nil {
		writeErr(w, 500, "runtime not initialized")
		return
	}
	writeJSON(w, 200, s.cfg.Runtime)
}

// security headers endpoint
//
// Response:
//
//	{
//	  "headers": {
//	    "x-sec-navigation-state": "80d51dc5-af20-46fa-a7bb-e6a8f3f80065"
//	  },
//	  "count": 1,
//	  "generated_at": "2026-09-30T..."
//	}
func (s *Server) handleSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.cfg.Runtime == nil {
		writeErr(w, 500, "runtime not initialized")
		return
	}

	headers := s.cfg.Runtime.SecurityHeaders
	if headers == nil {
		headers = map[string]string{}
	}

	writeJSON(w, 200, map[string]any{
		"headers":      headers,
		"count":        len(headers),
		"generated_at": s.cfg.Runtime.GeneratedAt,
		"source":       s.cfg.Runtime.Source,
	})
}

func (s *Server) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "POST required")
		return
	}
	if s.cfg.Encryptor == nil {
		writeErr(w, 500, "encryptor not initialized")
		return
	}

	var req struct {
		RawToken string `json:"rawToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "invalid json: "+err.Error())
		return
	}
	req.RawToken = strings.TrimSpace(req.RawToken)
	if req.RawToken == "" {
		writeErr(w, 400, "rawToken is required")
		return
	}

	enc, err := s.cfg.Encryptor.Encrypt(req.RawToken)
	if err != nil {
		writeErr(w, 500, "encrypt failed: "+err.Error())
		return
	}
	cfg := s.cfg.Encryptor.Config()
	writeJSON(w, 200, map[string]any{
		"encrypted": enc,
		"version":   cfg.Version,
		"startAt":   cfg.StartAt,
		"length":    cfg.Length,
	})
}

func (s *Server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "POST required")
		return
	}
	if s.cfg.Encryptor == nil {
		writeErr(w, 500, "encryptor not initialized")
		return
	}

	var req struct {
		Encrypted string `json:"encrypted"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "invalid json: "+err.Error())
		return
	}
	raw, err := s.cfg.Encryptor.Decrypt(req.Encrypted)
	if err != nil {
		writeErr(w, 500, "decrypt failed: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"rawToken": raw})
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "POST required")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 1) URL থেকে fresh download (শুধু URL হলে)
	if strings.HasPrefix(s.cfg.Source, "http://") ||
		strings.HasPrefix(s.cfg.Source, "https://") {
		raw := s.cfg.DeobfPath + ".min.js"
		if err := httpDownload(s.cfg.Source, raw); err != nil {
			writeErr(w, 500, "download: "+err.Error())
			return
		}
		if err := runDeobf(s.cfg.WorkDir, raw, s.cfg.DeobfPath, s.cfg.KeepInfra); err != nil {
			writeErr(w, 500, "deobf: "+err.Error())
			return
		}
	}

	// 2) encryptor reload
	if err := s.cfg.Encryptor.Reload(s.cfg.DeobfPath); err != nil {
		writeErr(w, 500, "encryptor reload: "+err.Error())
		return
	}

	// 3) endpoints + methods + security headers re-extract
	if s.cfg.Runtime != nil {
		if res, err := extractor.ExtractFromFile(s.cfg.DeobfPath); err == nil {
			epMap := make(map[string]string, len(res.Endpoints))
			epMethodMap := make(map[string]string, len(res.Endpoints))
			for k, v := range res.Endpoints {
				epMap[k] = v.Path
				epMethodMap[k] = v.Method // ★★★ NEW ★★★
			}
			s.cfg.Runtime.Endpoints = epMap
			s.cfg.Runtime.EndpointMethods = epMethodMap // ★★★ NEW ★★★
			s.cfg.Runtime.RawPaths = res.AllPaths
			s.cfg.Runtime.GeneratedAt = time.Now().UTC()
			s.cfg.Runtime.SecurityHeaders = res.SecurityHeaders

			fmt.Printf("[RELOAD] endpoints: %d | methods: %d | sec_headers: %d\n",
				len(epMap), len(epMethodMap), len(res.SecurityHeaders))
		}
	}

	writeJSON(w, 200, map[string]any{
		"ok":                true,
		"reloaded":          time.Now().UTC(),
		"version":           s.cfg.Encryptor.Config().Version,
		"endpoints_count":   len(s.cfg.Runtime.Endpoints),
		"methods_count":     len(s.cfg.Runtime.EndpointMethods), // ★★★ NEW ★★★
		"sec_headers_count": len(s.cfg.Runtime.SecurityHeaders),
	})
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func httpDownload(url, dst string) error {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 90 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// হোমপেজ hit — cookie
	if origin := originOf(url); origin != "" {
		_ = doGet(ctx, client, origin, nil)
	}

	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	return doGet(ctx, client, url, f)
}

func originOf(full string) string {
	i := strings.Index(full, "://")
	if i < 0 {
		return ""
	}
	rest := full[i+3:]
	j := strings.Index(rest, "/")
	if j < 0 {
		return full + "/"
	}
	return full[:i+3] + rest[:j] + "/"
}

func doGet(ctx context.Context, c *http.Client, url string, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "+
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,"+
		"image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Referer", originOf(url))
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s -> %s", url, resp.Status)
	}
	if w != nil {
		_, err = io.Copy(w, resp.Body)
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func runDeobf(workDir, in, out string, keepInfra bool) error {
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
