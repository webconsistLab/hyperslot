// main.go - সম্পূর্ণ আপডেটেড ফাইল
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/proxy"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func startTunnel() {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		// Windows: PowerShell script
		cmd = exec.Command(
			"powershell",
			"-ExecutionPolicy", "Bypass",
			"-File", "tunnel.ps1",
		)
	case "linux", "darwin":
		// Linux/macOS: bash script
		cmd = exec.Command("bash", "tunnel.sh")
	default:
		log.Printf("[TUNNEL] Unsupported OS: %s — skipping", runtime.GOOS)
		return
	}

	err := cmd.Start()
	if err != nil {
		log.Println("[TUNNEL] Start failed:", err)
		return
	}
	log.Println("[TUNNEL] Started. PID:", cmd.Process.Pid)
}

// ============================================================
// ১. ডেটা মডেল (Data Models)
// ============================================================

type Account struct {
	ID            string     `json:"id"`
	SL            int        `json:"sl"`
	UserID        string     `json:"user_id"`
	Phone         string     `json:"phone"`
	Password      string     `json:"password"`
	IP            string     `json:"ip"`
	Status        string     `json:"status"`
	OTP           string     `json:"otp"`
	OTPVerified   bool       `json:"otp_verified"`
	SignToken     string     `json:"sign_token"`
	AccessToken   string     `json:"access_token"`
	RequestID     string     `json:"request_id"`
	ReserveToken  string     `json:"reserve_token"`
	ReservationID string     `json:"reservation_id"`
	AppointmentID string     `json:"appointment_id"`
	PaymentLink   string     `json:"payment_link"`
	PayToken      string     `json:"pay_token"`
	OTPFetchedAt  *time.Time `json:"otp_fetched_at,omitempty"`
	PaymentLinkAt *time.Time `json:"payment_link_at,omitempty"`

	UploadFiles         []string `json:"upload_files"`
	ConfirmationID      string   `json:"confirmation_id"`
	MissionID           string   `json:"mission_id"`
	Mission             string   `json:"mission"`
	IvacCenter          string   `json:"ivac_center"`
	AppointmentDate     string   `json:"appointment_date"`
	AppointmentDates    []string `json:"appointment_dates,omitempty"`
	UploadedFiles       []string `json:"uploaded_files"` // ← নতুন (সফল আপলোড ট্র্যাক)
	FileUploadConfirmed bool     `json:"file_upload_confirmed"`
	UploadEnd           bool     `json:"upload_end"`
	PaymentConfirm      bool     `json:"payment_confirm"`
	SlotOpen            bool     `json:"slot_open"`
}

type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Role      string    `json:"role"`
	Locked    bool      `json:"locked"`
	CreatedAt time.Time `json:"created_at"`
}

type Config struct {
	RetryCount        int  `json:"retry_count"`
	RetryDelaySec     int  `json:"retry_delay_sec"`
	Concurrency       int  `json:"concurrency"`
	SigninConcurrency int  `json:"signin_concurrency"`
	DelaySec          int  `json:"delay_sec"`
	ReserveRetryDelay int  `json:"reserve_retry_delay"`
	EnableRetry       bool `json:"enable_retry"`

	TokenRetryCount    int  `json:"token_retry_count"`
	TokenRetryDelaySec int  `json:"token_retry_delay_sec"`
	TokenEnableRetry   bool `json:"token_enable_retry"`

	EnableWarmup bool `json:"enable_warmup"`
}

type Storage struct {
	mu       sync.Mutex
	Accounts []Account `json:"accounts"`
	Users    []User    `json:"users"`
	Config   Config    `json:"config"`
	filePath string
}

// uploadResult struct for concurrent upload results
type uploadResult struct {
	filename string
	success  bool
}

// uploadSingleFile - একটি single ফাইল আপলোড করার জন্য হেলপার ফাংশন
func uploadSingleFile(ctx context.Context, accountID, method, urlStr string, baseHeaders map[string]string, fileName string, isPrimary bool, phone, ip string) bool {
	acc := storage.GetAccount(accountID)
	if acc == nil {
		log.Printf("[UPLOAD] ❌ Account %s not found", accountID)
		return false
	}

	// প্রতিটি ফাইলের জন্য আলাদা টোকেন fetch করুন
	uploadToken, err := fetchUploadToken(ctx, phone, ip)
	if err != nil {
		log.Printf("[UPLOAD] ❌ Failed to get upload token for %s: %v", fileName, err)
		return false
	}
	log.Printf("[UPLOAD] Upload token received for %s", fileName)

	filePath := filepath.Join("uploads", phone, fileName)
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("[UPLOAD] Failed to read file %s: %v", filePath, err)
		return false
	}

	// Multipart form তৈরি করুন
	var b bytes.Buffer
	boundary := "----WebKitFormBoundary" + randomString(16)
	writer := multipart.NewWriter(&b)
	writer.SetBoundary(boundary)

	fileHeader := make(textproto.MIMEHeader)
	fileHeader.Set("Content-Disposition", fmt.Sprintf(`form-data; name="files"; filename="%s"`, filepath.Base(fileName)))
	fileHeader.Set("Content-Type", "application/pdf")
	part, err := writer.CreatePart(fileHeader)
	if err != nil {
		log.Printf("[UPLOAD] Failed to create form part: %v", err)
		return false
	}
	if _, err := part.Write(fileContent); err != nil {
		log.Printf("[UPLOAD] Failed to write file content: %v", err)
		return false
	}

	// isPrimary ফিল্ড যোগ করুন
	if isPrimary {
		writer.WriteField("isPrimary", "true")
	} else {
		writer.WriteField("isPrimary", "false")
	}
	writer.Close()

	// হেডার তৈরি করুন
	contentType := "multipart/form-data; boundary=" + boundary
	headersCopy := map[string]string{}
	for k, v := range baseHeaders {
		headersCopy[k] = v
	}
	headersCopy["x-token"] = uploadToken
	headersCopy["Content-Type"] = contentType

	// রিকুয়েস্ট পাঠান
	resp, err := doRequestWithRetry(ctx, method, urlStr, b.Bytes(), headersCopy, ip, 20)
	if err != nil {
		log.Printf("[UPLOAD] Upload request failed for %s: %v", fileName, err)
		return false
	}

	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 399 {
		log.Printf("[UPLOAD] ✅ File uploaded successfully: %s | response: %s", fileName, string(respBody))
		// UploadedFiles এ যোগ করুন
		addUploadedFile(accountID, fileName)
		return true
	} else if resp.StatusCode == 409 {
		// ★★★ 409 এর response body চেক করুন ★★★
		bodyStr := string(respBody)

		// যদি "already exists" বা "already uploaded" এরকম মেসেজ থাকে তাহলে success
		if strings.Contains(strings.ToLower(bodyStr), "already exists") ||
			strings.Contains(strings.ToLower(bodyStr), "already uploaded") {
			log.Printf("[UPLOAD] ⏭️ File already exists (409): %s, considering success | response: %s", fileName, bodyStr)
			addUploadedFile(accountID, fileName)
			return true
		}

		// ★★★ অন্যথায় (যেমন "Invalid web file, missing application id") retry করুন ★★★
		log.Printf("[UPLOAD] ⚠️ 409 with non-exists message: %s | response: %s - treating as failure", fileName, bodyStr)
		return false
	} else if resp.StatusCode == 400 {
		log.Printf("[UPLOAD] ❌ File upload failed with status %d: %s | response: %s", resp.StatusCode, fileName, string(respBody))
		return false
	} else {
		log.Printf("[UPLOAD] ❌ File upload failed with status %d: %s | response: %s", resp.StatusCode, fileName, string(respBody))
		return false
	}
}

// addUploadedFile - ফাইলের নাম UploadedFiles স্লাইসে যোগ করুন
func addUploadedFile(accountID, fileName string) {
	acc := storage.GetAccount(accountID)
	if acc == nil {
		return
	}
	for _, f := range acc.UploadedFiles {
		if f == fileName {
			return
		}
	}
	newList := append(acc.UploadedFiles, fileName)
	storage.UpdateAccountField(accountID, "uploaded_files", strings.Join(newList, ",")) // ← "uploaded_files" ফিল্ড নেই!
}

// ============================================================
// ২. গ্লোবাল ভেরিয়েবল
// ============================================================

var (
	storage      *Storage
	runningTasks = make(map[string]context.CancelFunc)
	tasksMu      sync.Mutex
	jwtSecret    = []byte("hyper-panel-2026-masud")
	clientCache  sync.Map

	// ★★★ NEW — Extractor URL (main() এ set হবে) ★★★
	extractorBaseURL = "http://127.0.0.1:1111"
)

// ============================================================
// ৩. স্টোরেজ ফাংশন (অপরিবর্তিত)
// ============================================================

func NewStorage(filePath string) *Storage {
	return &Storage{
		filePath: filePath,
		Config: Config{
			RetryCount:         100,
			RetryDelaySec:      2,
			Concurrency:        3,
			SigninConcurrency:  1,
			DelaySec:           1,
			ReserveRetryDelay:  21,
			EnableRetry:        true,
			TokenRetryCount:    3,
			TokenRetryDelaySec: 2,
			TokenEnableRetry:   true,
			EnableWarmup:       true,
		},
	}
}

func (s *Storage) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	log.Printf("[DEBUG] Loading data from %s", s.filePath)
	file, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[DEBUG] File not found, initializing empty storage")
			s.Accounts = []Account{}
			s.Users = []User{}
			s.Config = Config{
				RetryCount:         3,
				RetryDelaySec:      2,
				Concurrency:        3,
				SigninConcurrency:  1,
				DelaySec:           1,
				ReserveRetryDelay:  21,
				EnableRetry:        true,
				TokenRetryCount:    3,
				TokenRetryDelaySec: 2,
				TokenEnableRetry:   true,
				EnableWarmup:       true,
			}
			admin := User{ID: "1", Username: "admin", Password: hashPassword("Msd@458@"), Role: "admin", Locked: false, CreatedAt: time.Now()}
			s.Users = append(s.Users, admin)
			return s.saveLocked()
		}
		return err
	}
	if len(file) == 0 {
		s.Accounts = []Account{}
		s.Users = []User{}
		s.Config = Config{
			RetryCount:         3,
			RetryDelaySec:      2,
			Concurrency:        3,
			SigninConcurrency:  1,
			DelaySec:           1,
			ReserveRetryDelay:  21,
			EnableRetry:        true,
			TokenRetryCount:    3,
			TokenRetryDelaySec: 2,
			TokenEnableRetry:   true,
			EnableWarmup:       true,
		}
		admin := User{ID: "1", Username: "admin", Password: hashPassword("Msd@458@"), Role: "admin", Locked: false, CreatedAt: time.Now()}
		s.Users = append(s.Users, admin)
		return s.saveLocked()
	}
	if err := json.Unmarshal(file, &s); err != nil {
		return err
	}
	s.renumberAccountsLocked()
	if len(s.Users) == 0 {
		admin := User{ID: "1", Username: "admin", Password: hashPassword("Msd@458@"), Role: "admin", Locked: false, CreatedAt: time.Now()}
		s.Users = append(s.Users, admin)
		for i := range s.Accounts {
			s.Accounts[i].UserID = admin.ID
		}
		return s.saveLocked()
	}
	if len(s.Users) > 0 {
		adminID := s.Users[0].ID
		for i := range s.Accounts {
			if s.Accounts[i].UserID == "" {
				s.Accounts[i].UserID = adminID
			}
		}
		return s.saveLocked()
	}
	return nil
}

func (s *Storage) saveLocked() error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.filePath, data, 0644)
}

func (s *Storage) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}
func (s *Storage) renumberAccountsLocked() {
	for i := range s.Accounts {
		s.Accounts[i].SL = i + 1
	}
}
func (s *Storage) AddAccount(acc Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Accounts = append(s.Accounts, acc)
	s.renumberAccountsLocked()
	return s.saveLocked()
}

func (s *Storage) DeleteAccount(id string) error {
	// ★ শুধু এই account এর task cancel (IDs immutable, অন্যের task safe)
	tasksMu.Lock()
	if cancel, ok := runningTasks[id]; ok {
		cancel()
		delete(runningTasks, id)
		log.Printf("[DELETE] Cancelled task for account %s", id)
	}
	tasksMu.Unlock()
	time.Sleep(200 * time.Millisecond)

	s.mu.Lock()
	defer s.mu.Unlock()

	for i, acc := range s.Accounts {
		if acc.ID == id {
			s.Accounts = append(s.Accounts[:i], s.Accounts[i+1:]...)
			break
		}
	}

	// SL renumber (IDs unchanged)
	s.renumberAccountsLocked()
	return s.saveLocked()
}

func (s *Storage) DeleteAllAccounts() error {
	tasksMu.Lock()
	for id, cancel := range runningTasks {
		cancel()
		delete(runningTasks, id)
		log.Printf("[DELETE ALL] Cancelled task for account %s", id)
	}
	tasksMu.Unlock()
	time.Sleep(300 * time.Millisecond)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.Accounts = []Account{}
	return s.saveLocked()
}

func (s *Storage) GetAccount(id string) *Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Accounts {
		if s.Accounts[i].ID == id {
			return &s.Accounts[i]
		}
	}
	return nil
}

func (s *Storage) GetAccountsByUser(userID string) []Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	var res []Account
	for _, acc := range s.Accounts {
		if acc.UserID == userID {
			res = append(res, acc)
		}
	}
	return res
}

func (s *Storage) UpdateAccountField(id, field, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, acc := range s.Accounts {
		if acc.ID == id {
			switch field {
			case "phone":
				s.Accounts[i].Phone = value
			case "password":
				s.Accounts[i].Password = value
			case "ip":
				s.Accounts[i].IP = value
			case "status":
				s.Accounts[i].Status = value
			case "otp":
				s.Accounts[i].OTP = value
			case "otp_verified":
				s.Accounts[i].OTPVerified = value == "true"
			case "sign_token":
				s.Accounts[i].SignToken = value
			case "access_token":
				s.Accounts[i].AccessToken = value
			case "request_id":
				s.Accounts[i].RequestID = value
			case "reserve_token":
				s.Accounts[i].ReserveToken = value
			case "reservation_id":
				s.Accounts[i].ReservationID = value
			case "appointment_id":
				s.Accounts[i].AppointmentID = value
			case "payment_link":
				s.Accounts[i].PaymentLink = value
			case "pay_token":
				s.Accounts[i].PayToken = value
			case "confirmation_id":
				s.Accounts[i].ConfirmationID = value
			case "mission_id":
				s.Accounts[i].MissionID = value
			case "upload_files":
				s.Accounts[i].UploadFiles = strings.Split(value, ",")
			case "uploaded_files": // ← এই লাইন যোগ করুন
				if value == "" {
					s.Accounts[i].UploadedFiles = []string{}
				} else {
					s.Accounts[i].UploadedFiles = strings.Split(value, ",")
				}
			case "mission":
				s.Accounts[i].Mission = value
			case "ivac_center":
				s.Accounts[i].IvacCenter = value
			default:
				return fmt.Errorf("unknown field: %s", field)
			}
			return s.saveLocked()
		}
	}
	return fmt.Errorf("account not found")
}

func (s *Storage) UpdateAccountOTPFetchedAt(id string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Accounts {
		if s.Accounts[i].ID == id {
			s.Accounts[i].OTPFetchedAt = &t
			return s.saveLocked()
		}
	}
	return fmt.Errorf("account not found")
}

func (s *Storage) UpdateAccountPaymentLinkAt(id string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Accounts {
		if s.Accounts[i].ID == id {
			s.Accounts[i].PaymentLinkAt = &t
			return s.saveLocked()
		}
	}
	return fmt.Errorf("account not found")
}

func (s *Storage) GetUserByUsername(username string) *User {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Users {
		if s.Users[i].Username == username {
			return &s.Users[i]
		}
	}
	return nil
}

func (s *Storage) GetUserByID(id string) *User {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Users {
		if s.Users[i].ID == id {
			return &s.Users[i]
		}
	}
	return nil
}

func (s *Storage) AddUser(user User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Users = append(s.Users, user)
	return s.saveLocked()
}

func (s *Storage) UpdateUser(id string, username, password, role string, locked *bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range s.Users {
		if u.ID == id {
			if username != "" {
				s.Users[i].Username = username
			}
			if password != "" {
				s.Users[i].Password = hashPassword(password)
			}
			if role != "" {
				s.Users[i].Role = role
			}
			if locked != nil {
				s.Users[i].Locked = *locked
			}
			return s.saveLocked()
		}
	}
	return fmt.Errorf("user not found")
}

func (s *Storage) ReloadConfig() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}
	var temp struct {
		Config Config `json:"config"`
	}
	if err := json.Unmarshal(file, &temp); err != nil {
		return err
	}
	s.Config = temp.Config
	return s.saveLocked()
}

func (s *Storage) DeleteUser(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range s.Users {
		if u.ID == id {
			if u.Role == "admin" {
				adminCount := 0
				for _, u2 := range s.Users {
					if u2.Role == "admin" {
						adminCount++
					}
				}
				if adminCount <= 1 {
					return fmt.Errorf("cannot delete the only admin")
				}
			}
			s.Users = append(s.Users[:i], s.Users[i+1:]...)
			return s.saveLocked()
		}
	}
	return fmt.Errorf("user not found")
}

func generateAccountID() string {
	return randomString(12)
}

func generateUserID() string {
	storage.mu.Lock()
	defer storage.mu.Unlock()

	maxID := 0
	for _, u := range storage.Users {
		if id, err := strconv.Atoi(u.ID); err == nil && id > maxID {
			maxID = id
		}
	}
	return strconv.Itoa(maxID + 1)
}

func hashPassword(pw string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("bcrypt error:", err)
	}
	return string(hash)
}

func checkPasswordHash(pw, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw))
	return err == nil
}

// ============================================================
// ৪. JWT
// ============================================================

type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Locked   bool   `json:"locked"`
	jwt.RegisteredClaims
}

func generateToken(user User) (string, error) {
	claims := Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		Locked:   user.Locked,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func validateToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

// ============================================================
// ৫. মিডলওয়্যার
// ============================================================

type contextKey string

const userContextKey contextKey = "user"

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}
		claims, err := validateToken(parts[1])
		if err != nil {
			http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), userContextKey, claims)
		next(w, r.WithContext(ctx))
	}
}

func adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(userContextKey).(*Claims)
		if !ok || claims.Role != "admin" {
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

func getUserFromContext(r *http.Request) (*Claims, bool) {
	claims, ok := r.Context().Value(userContextKey).(*Claims)
	return claims, ok
}

// ============================================================
// ৬. HTTP ক্লায়েন্ট (ক্যাশ সহ)
// ============================================================

func newHTTPClient(proxyStr string) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	}

	if proxyStr != "" {
		if !strings.HasPrefix(proxyStr, "http://") && !strings.HasPrefix(proxyStr, "https://") && !strings.HasPrefix(proxyStr, "socks5://") {
			proxyStr = "http://" + proxyStr
		}
		proxyURL, err := url.Parse(proxyStr)
		if err == nil {
			if proxyURL.Scheme == "socks5" {
				log.Printf("[PROXY] Using SOCKS5: %s", proxyStr)
				var auth *proxy.Auth
				if proxyURL.User != nil {
					pass, _ := proxyURL.User.Password()
					auth = &proxy.Auth{
						User:     proxyURL.User.Username(),
						Password: pass,
					}
				}
				dialer, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
				if err == nil {
					transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
						return dialer.(proxy.ContextDialer).DialContext(ctx, network, addr)
					}
				} else {
					log.Printf("[WARN] SOCKS5 dialer creation failed: %v", err)
				}
			} else {
				log.Printf("[PROXY] Using HTTP(S): %s", proxyStr)
				transport.Proxy = http.ProxyURL(proxyURL)
			}
		} else {
			log.Printf("[WARN] Invalid proxy URL: %s, using direct connection", proxyStr)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}
}

func getHTTPClient(proxyStr string) *http.Client {
	if v, ok := clientCache.Load(proxyStr); ok {
		return v.(*http.Client)
	}
	client := newHTTPClient(proxyStr)
	clientCache.Store(proxyStr, client)
	return client
}

func warmUpConnection(proxyStr string) {
	client := getHTTPClient(proxyStr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.ivacbd.com/cdn-cgi/speculation", nil)
	if err != nil {
		log.Printf("[WARMUP] Failed to create request for proxy %s: %v", proxyStr, err)
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[WARMUP] Failed to warm up connection for proxy %s: %v", proxyStr, err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	log.Printf("[WARMUP] Connection warmed up for proxy %s", proxyStr)
}

// ============================================================
// ৭. কনফিগ হেলপার (রিয়েল-টাইম রিলোড)
// ============================================================

func getRetryCount() int {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	return storage.Config.RetryCount
}

func getRetryDelay() int {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	return storage.Config.RetryDelaySec
}

func getEnableRetry() bool {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	return storage.Config.EnableRetry
}

func getConcurrency() int {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	return storage.Config.Concurrency
}

func getSigninConcurrency() int {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	return storage.Config.SigninConcurrency
}

func getDelaySec() int {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	return storage.Config.DelaySec
}

func getReserveRetryDelay() int {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	return storage.Config.ReserveRetryDelay
}

func getTokenRetryCount() int {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	return storage.Config.TokenRetryCount
}

func getTokenRetryDelay() int {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	return storage.Config.TokenRetryDelaySec
}

func getTokenEnableRetry() bool {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	return storage.Config.TokenEnableRetry
}

func getEnableWarmup() bool {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	return storage.Config.EnableWarmup
}

var methodOverride = map[string]string{
	"appointment_booking_config": "POST",
	// "another_endpoint": "POST",   ← এখানে যোগ করুন
}

// ============================================================
// ৮. ডায়নামিক এন্ডপয়েন্ট ফেচ ও পার্সিং
// ============================================================

func fetchEndpoint(keyword string) (method, urlStr string, headers map[string]string, bodyTemplate string, err error) {
	if err := endpointCache.ensureLoaded(); err != nil {
		return "", "", nil, "", fmt.Errorf("endpoint cache unavailable: %w", err)
	}

	key := resolveEndpointKey(keyword)
	if key == "" {
		return "", "", nil, "", fmt.Errorf("no endpoint found for keyword %q", keyword)
	}

	path, ok := endpointCache.Get(key)
	if !ok {
		return "", "", nil, "", fmt.Errorf("endpoint key %q not found in cache", key)
	}

	urlStr = endpointCache.BuildFullURL(path)

	// ★★★ NEW — JS-detected method, fallback সহ ★★★
	method = endpointCache.GetMethod(key)
	if method == "" {
		method = methodFallback(key)
	}
	method = strings.ToUpper(method)

	// ★★★ HARDCODED OVERRIDE — যেসব endpoint-এ JS ভুল method দেয় ★★★
	if fixed, ok := methodOverride[key]; ok {
		method = fixed
		log.Printf("[ENDPOINT] ⚠️  method override for %q: %s → %s", key, endpointCache.GetMethod(key), fixed)
	}

	headers = map[string]string{
		"Accept": "application/json, text/plain, */*",
	}
	if method == "POST" || method == "PUT" || method == "PATCH" {
		headers["Content-Type"] = "application/json"
	}
	bodyTemplate = ""

	log.Printf("[ENDPOINT] keyword=%q → key=%q → %s %s", keyword, key, method, urlStr)
	return method, urlStr, headers, bodyTemplate, nil
}

// ★★★ NEW — JS-এ method detect না হলে fallback ★★★
func methodFallback(key string) string {
	// ★★★ HARDCODED overrides (JS detect ভুল হলে) ★★★
	switch key {
	case "appointment_booking_config":
		return "POST" // server POST চায়, JS বলে GET
	}

	// বাকি সব default
	switch key {
	case "file_slot_status", "file_overview", "booking_config":
		return "GET"
	default:
		return "POST"
	}
}

// resolveEndpointKey — keyword কে endpoint key তে map করে
//
// আপনার runAutomation-এ যে keyword গুলো ব্যবহার হয় সেগুলো handle করে:
//
//	"/auth/"        → signin
//	"/otp/"         → otp_verify_signin
//	"status"        → file_slot_status
//	"file/up"       → file_upload
//	"nt-booking"    → appointment_booking_config
//	"et-booking"    → booking_config
//	"/slots/"       → reserve_slot
//	"epay"          → payment_dg_epay_initiate
// ═══════════════════════════════════════════════════════════════
// resolveEndpointKey — keyword → endpoint key
// ═══════════════════════════════════════════════════════════════

func resolveEndpointKey(keyword string) string {
	kw := strings.ToLower(strings.TrimSpace(keyword))

	// সরাসরি match
	switch kw {
	case "/auth/", "auth", "signin":
		return "signin"
	case "/otp/", "otp", "otp-verify", "verify-otp":
		return "otp_verify_signin"
	case "status", "file/status", "slot-status", "file-status":
		return "file_slot_status"
	case "file/up", "upload", "file/upload", "file-upload":
		return "file_upload"
	case "over-view", "overview", "file/overview":
		return "file_overview"
	case "nt-booking", "appointment-booking-config", "appointment-booking":
		return "appointment_booking_config"
	case "et-booking", "get-booking", "booking-config", "get-booking-config":
		return "booking_config"
	case "/slots/", "slots", "reserve", "reserve_slot", "reserve-slot":
		return "reserve_slot"
	case "epay", "dg-epay", "payment", "payment-initiate", "initiate":
		return "payment_dg_epay_initiate"
	case "appointment", "/appointment":
		return "appointment"
	}

	// substring-based fallback
	c := endpointCache
	c.mu.RLock()
	defer c.mu.RUnlock()
	for key := range c.endpoints {
		if strings.Contains(key, kw) || strings.Contains(kw, key) {
			return key
		}
	}
	return ""
}

func replacePlaceholders(text string, account *Account, extra map[string]string) string {
	pairs := []string{
		"{{.Phone}}", account.Phone,
		"{{.Password}}", account.Password,
		"{{.SignToken}}", account.SignToken,
		"{{.AccessToken}}", account.AccessToken,
		"{{.RequestID}}", account.RequestID,
		"{{.OTP}}", account.OTP,
		"{{.ReserveToken}}", account.ReserveToken,
		"{{.ReservationID}}", account.ReservationID,
		"{{.AppointmentID}}", account.AppointmentID,
		"{{.PayToken}}", account.PayToken,
		"{{.ConfirmationID}}", account.ConfirmationID,
		"{{.MissionID}}", account.MissionID,
		"{{.Mission}}", account.Mission,
		"{{.IvacCenter}}", account.IvacCenter,
	}
	if extra != nil {
		for k, v := range extra {
			pairs = append(pairs, "{{."+k+"}}", v)
		}
	}
	replacer := strings.NewReplacer(pairs...)
	return replacer.Replace(text)
}

// ============================================================
// ★★★ NEW — Security Headers Cache + Fetch (from extractor) ★★★
// ============================================================

type secHeadersCache struct {
	mu        sync.RWMutex
	headers   map[string]string
	fetchedAt time.Time
	ttl       time.Duration
}

var secCache = &secHeadersCache{
	headers:   make(map[string]string),
	fetchedAt: time.Time{},
	ttl:       30 * time.Second,
}

// fetchSecurityHeaders — extractor থেকে dynamic x-sec-* headers আনে (30s cache)
func fetchSecurityHeaders(ctx context.Context) (map[string]string, error) {
	// ★ cache fresh হলে return
	secCache.mu.RLock()
	if len(secCache.headers) > 0 && time.Since(secCache.fetchedAt) < secCache.ttl {
		cached := make(map[string]string, len(secCache.headers))
		for k, v := range secCache.headers {
			cached[k] = v
		}
		secCache.mu.RUnlock()
		return cached, nil
	}
	secCache.mu.RUnlock()

	// ★ fresh fetch from extractor
	url := extractorBaseURL + "/security-headers"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("extractor fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("extractor returned %d", resp.StatusCode)
	}

	var result struct {
		Headers map[string]string `json:"headers"`
		Count   int               `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	// ★ cache update
	secCache.mu.Lock()
	secCache.headers = result.Headers
	secCache.fetchedAt = time.Now()
	secCache.mu.Unlock()

	log.Printf("[SEC-HEADERS] fetched %d headers from extractor: %v", result.Count, result.Headers)
	return result.Headers, nil
}

// injectSecurityHeaders — headers map-এ dynamic sec headers যোগ করে (fallback সহ)
func injectSecurityHeaders(ctx context.Context, headers map[string]string) {
	secHeaders, err := fetchSecurityHeaders(ctx)
	if err == nil && len(secHeaders) > 0 {
		for k, v := range secHeaders {
			if _, exists := headers[k]; !exists {
				headers[k] = v
			}
		}
		// ★★★ Static fallback — extractor-এ না থাকলেও যোগ হবে ★★★
		if _, exists := headers["x-v-request-meta"]; !exists {
			headers["x-v-request-meta"] = "windos.s"
		}
		return
	}

	// ★ fallback — extractor down হলে hardcoded
	log.Printf("[SEC-HEADERS] extractor unavailable (%v), using fallback", err)
	if _, exists := headers["x-sec-navigation-state"]; !exists {
		headers["x-sec-navigation-state"] = "80d51dc5-af20-46fa-a7bb-e6a8f3f80065"
	}
	if _, exists := headers["x-sec-runtime-state"]; !exists {
		headers["x-sec-runtime-state"] = "v1.5a4c8831.9a53.47ed.b579.042a2c0cee5a"
	}
	// ★★★ NEW ★★★
	if _, exists := headers["x-v-request-meta"]; !exists {
		headers["x-v-request-meta"] = "windos.s"
	}
}

func prepareRequestWithAuth(ctx context.Context, keyword string, account *Account, extra map[string]string, authToken string) (method, urlStr string, headers map[string]string, body []byte, err error) {
	method, urlStr, rawHeaders, bodyTemplate, err := fetchEndpoint(keyword)
	if err != nil {
		return "", "", nil, nil, err
	}
	headers = make(map[string]string)
	for k, v := range rawHeaders {
		headers[k] = replacePlaceholders(v, account, extra)
	}
	if authToken != "" {
		headers["Authorization"] = "Bearer " + authToken
	}

	// ★★★ NEW — dynamic security headers inject (x-sec-navigation-state, x-sec-runtime-state) ★★★
	injectSecurityHeaders(ctx, headers)

	if bodyTemplate != "" {
		bodyStr := replacePlaceholders(bodyTemplate, account, extra)
		body = []byte(bodyStr)
	} else {
		body = nil
	}
	return method, urlStr, headers, body, nil
}

// ============================================================
// ৯. রিট্রাই ও কনকারেন্ট হেলপার (অপরিবর্তিত)
// ============================================================

func doRequestWithRetry(ctx context.Context, method, urlStr string, body []byte, headers map[string]string, ip string, maxRetry ...int) (*http.Response, error) {
	var lastErr error
	attempt := 1
	for {
		retryCount := getRetryCount()
		retryDelay := getRetryDelay()
		enableRetry := getEnableRetry()
		if len(maxRetry) > 0 && maxRetry[0] >= 0 {
			retryCount = maxRetry[0]
		} else if !enableRetry || retryCount <= 0 {
			retryCount = 1
		}
		if retryCount < 1 {
			retryCount = 1
		}
		if retryDelay < 1 {
			retryDelay = 2
		}

		for attempt <= retryCount {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			log.Printf("[RETRY] Attempt %d/%d for %s", attempt, retryCount, urlStr)
			client := getHTTPClient(ip)

			var reqBody io.Reader
			// ★★★ NEW — GET/HEAD/DELETE-এ body পাঠাই না ★★★
			if body != nil && len(body) > 0 {
				if method == "POST" || method == "PUT" || method == "PATCH" {
					reqBody = bytes.NewReader(body)
				}
			}

			req, err := http.NewRequestWithContext(ctx, method, urlStr, reqBody)
			if err != nil {
				log.Printf("[RETRY] Request build error: %v", err)
				lastErr = err
				attempt++
				if attempt <= retryCount {
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(time.Duration(retryDelay) * time.Second):
					}
					continue
				}
				return nil, err
			}

			for k, v := range headers {
				req.Header.Set(k, v)
			}
			if _, ok := headers["User-Agent"]; !ok {
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			}

			resp, err := client.Do(req)
			if err != nil {
				log.Printf("[RETRY] Request error: %v", err)
				lastErr = err
				attempt++
				if attempt <= retryCount {
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(time.Duration(retryDelay) * time.Second):
					}
					continue
				}
				return nil, err
			}

			if resp.StatusCode == 500 || resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504 {
				// ★★★ response body পড়ুন close করার আগে ★★★
				bodyBytes, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				log.Printf("[RETRY] Got %d, body: %s", resp.StatusCode, string(bodyBytes))
				log.Printf("[RETRY] Request URL: %s", urlStr)
				log.Printf("[RETRY] Request body was: %s", string(body))
				log.Printf("[RETRY] Request headers: %v", headers)

				attempt++
				if attempt <= retryCount {
					log.Printf("[RETRY] retrying in %d seconds...", retryDelay)
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(time.Duration(retryDelay) * time.Second):
					}
					continue
				}
				return resp, nil
			}
			return resp, nil
		}
		return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
	}
}

func doConcurrentRequests(ctx context.Context, method, urlStr string, body []byte, headers map[string]string, ip string, concurrency, delaySec int) (*http.Response, error) {
	if concurrency <= 0 {
		concurrency = getConcurrency()
	}
	if delaySec < 0 {
		delaySec = getDelaySec()
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if delaySec < 0 {
		delaySec = 0
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		resp *http.Response
		err  error
	}
	resultCh := make(chan result, concurrency)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			if index > 0 {
				time.Sleep(time.Duration(delaySec) * time.Second * time.Duration(index))
			}
			select {
			case <-ctx.Done():
				resultCh <- result{nil, ctx.Err()}
				return
			default:
			}
			resp, err := doRequestWithRetry(ctx, method, urlStr, body, headers, ip)
			if err != nil {
				resultCh <- result{nil, fmt.Errorf("request %d: %w", index, err)}
				return
			}
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				select {
				case resultCh <- result{resp, nil}:
					cancel()
				default:
					resp.Body.Close()
				}
			} else {
				bodyBytes, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				errMsg := fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
				resultCh <- result{nil, fmt.Errorf("request %d failed: %s", index, errMsg)}
			}
		}(i)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var firstSuccess *http.Response
	var errors []error
	for res := range resultCh {
		if res.err != nil {
			errors = append(errors, res.err)
		} else if res.resp != nil {
			if firstSuccess == nil {
				firstSuccess = res.resp
				return firstSuccess, nil
			}
		}
	}
	if firstSuccess != nil {
		return firstSuccess, nil
	}
	if len(errors) > 0 {
		return nil, fmt.Errorf("all concurrent requests failed: %v", errors)
	}
	return nil, fmt.Errorf("no response")
}

// ============================================================
// ১০. টোকেন ফেচ ফাংশন (অপরিবর্তিত)
// ============================================================

func fetchSignToken(ctx context.Context, phone, ip string) (string, error) {
	log.Printf("[SIGN-TOKEN] 🔍 requesting from local pool...")
	token, err := localPoolFetch(ctx, "/captcha/get-encrypted", "encrypted", "")
	if err != nil {
		log.Printf("[SIGN-TOKEN] ❌ failed: %v", err)
		return "", fmt.Errorf("sign token unavailable: %w", err)
	}
	log.Printf("[SIGN-TOKEN] ✅ encrypted received (len=%d)", len(token))
	return token, nil
}

func fetchOTP(ctx context.Context, phone, ip string) (string, error) {
	urlStr := fmt.Sprintf("https://hyperslot-otp-358970714333.us-central1.run.app/otp/read/?phone=%s", phone)
	headers := map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
	for attempt := 1; ; attempt++ {
		retryCount := getTokenRetryCount()
		retryDelay := getTokenRetryDelay()
		enableRetry := getTokenEnableRetry()
		if !enableRetry || retryCount <= 0 {
			retryCount = 1
		}
		if retryDelay < 1 {
			retryDelay = 2
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		resp, err := doRequestWithRetry(ctx, "GET", urlStr, nil, headers, "", 1)
		if err != nil {
			log.Printf("[FETCH OTP] Attempt %d: request error: %v", attempt, err)
			if attempt < retryCount {
				time.Sleep(time.Duration(retryDelay) * time.Second)
				continue
			}
			return "", fmt.Errorf("fetch OTP failed: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			log.Printf("[FETCH OTP] Attempt %d: JSON parse error: %v", attempt, err)
			if attempt < retryCount {
				time.Sleep(time.Duration(retryDelay) * time.Second)
				continue
			}
			return "", fmt.Errorf("JSON parse failed: %w", err)
		}
		otp := ""
		if o, ok := result["otp"].(string); ok && o != "" {
			otp = o
		}
		if otp != "" {
			return otp, nil
		}
		if attempt >= retryCount {
			return "", fmt.Errorf("OTP not found after %d attempts", retryCount)
		}
		log.Printf("[FETCH OTP] Attempt %d: OTP not found, retrying...", attempt)
		time.Sleep(time.Duration(retryDelay) * time.Second)
	}
}

func saveOTPToExternal(ctx context.Context, phone, otp, ip string) error {
	if phone == "" || otp == "" {
		return fmt.Errorf("phone or OTP empty")
	}
	urlStr := fmt.Sprintf("https://hyperslot-otp-358970714333.us-central1.run.app/otp/?phone=%s&otp=%s",
		url.QueryEscape(phone), url.QueryEscape(otp))
	headers := map[string]string{"User-Agent": "Mozilla/5.0"}
	resp, err := doRequestWithRetry(ctx, "GET", urlStr, nil, headers, "", 3)
	if err != nil {
		return fmt.Errorf("external save failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("external API returned %d: %s", resp.StatusCode, string(body))
	}
	log.Printf("[SAVE OTP] OTP saved externally for %s (GET)", phone)
	return nil
}

func clearOTPFromServer(ctx context.Context, phone, ip string) {
	urlStr := fmt.Sprintf("https://hyperslot-otp-358970714333.us-central1.run.app/otp/remove/?phone=%s", phone)
	for attempt := 1; ; attempt++ {
		retryCount := getTokenRetryCount()
		retryDelay := getTokenRetryDelay()
		enableRetry := getTokenEnableRetry()
		if !enableRetry || retryCount <= 0 {
			retryCount = 1
		}
		if retryDelay < 1 {
			retryDelay = 2
		}
		select {
		case <-ctx.Done():
			log.Printf("[CLEAR OTP] Context cancelled for %s", phone)
			return
		default:
		}
		resp, err := doRequestWithRetry(ctx, "GET", urlStr, nil, map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}, "", 1)
		if err != nil {
			log.Printf("[CLEAR OTP] Attempt %d: request error for %s: %v", attempt, phone, err)
			if attempt < retryCount {
				time.Sleep(time.Duration(retryDelay) * time.Second)
				continue
			}
			log.Printf("[CLEAR OTP] Failed to clear OTP for %s after %d attempts: %v", phone, retryCount, err)
			return
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 && resp.StatusCode != 404 {
			log.Printf("[CLEAR OTP] Attempt %d: External API returned %d for %s: %s", attempt, resp.StatusCode, phone, string(body))
			if attempt < retryCount {
				time.Sleep(time.Duration(retryDelay) * time.Second)
				continue
			}
			return
		}
		log.Printf("[CLEAR OTP] OTP cleared (or already cleared) for %s", phone)
		return
	}
}

// fetchReserveToken — local pool থেকে encrypted
func fetchReserveToken(ctx context.Context, phone, ip string) (string, error) {
	log.Printf("[RESERVE-TOKEN] 🔍 requesting from local pool...")
	token, err := localPoolFetch(ctx, "/captcha/get-encrypted", "encrypted", "")
	if err != nil {
		log.Printf("[RESERVE-TOKEN] ❌ failed: %v", err)
		return "", fmt.Errorf("reserve token unavailable: %w", err)
	}
	log.Printf("[RESERVE-TOKEN] ✅ encrypted received (len=%d)", len(token))
	return token, nil
}

// fetchPayToken — local pool থেকে raw
func fetchPayToken(ctx context.Context, phone, ip string) (string, error) {
	log.Printf("[PAY-TOKEN] 🔍 requesting from local pool...")
	token, err := localPoolFetch(ctx, "/captcha/get-raw", "raw", "")
	if err != nil {
		log.Printf("[PAY-TOKEN] ❌ failed: %v", err)
		return "", fmt.Errorf("pay token unavailable: %w", err)
	}
	log.Printf("[PAY-TOKEN] ✅ raw received (len=%d)", len(token))
	return token, nil
}

// fetchUploadToken — local pool থেকে raw
func fetchUploadToken(ctx context.Context, phone, ip string) (string, error) {
	log.Printf("[UPLOAD-TOKEN] 🔍 requesting from local pool...")
	token, err := localPoolFetch(ctx, "/captcha/get-raw", "raw", "")
	if err != nil {
		log.Printf("[UPLOAD-TOKEN] ❌ failed: %v", err)
		return "", fmt.Errorf("upload token unavailable: %w", err)
	}
	log.Printf("[UPLOAD-TOKEN] ✅ raw received (len=%d)", len(token))
	return token, nil
}

// ============================================================
// ১১. অটোমেশন অর্কেস্ট্রেটর (আপডেটেড)
// ============================================================

func dataMissing(acc *Account, step int) bool {
	switch step {
	case 1:
		return acc.SignToken == ""
	case 2:
		return acc.AccessToken == "" || acc.RequestID == ""
	case 3:
		return acc.OTP == "" && !acc.OTPVerified
	case 4:
		return !acc.OTPVerified
	case 5:
		return acc.ConfirmationID == ""
	case 6:
		return acc.AppointmentID == ""
	case 7:
		// ফাইল না থাকলে স্কিপ, থাকলে চেক করুন কোনটা আপলোড হয়নি
		if len(acc.UploadFiles) == 0 {
			return false
		}
		uploadedMap := make(map[string]bool)
		for _, f := range acc.UploadedFiles {
			uploadedMap[f] = true
		}
		for _, f := range acc.UploadFiles {
			if !uploadedMap[f] {
				return true
			}
		}
		return false
	case 8:
		return acc.MissionID == ""
	case 9:
		// অ্যাপয়েন্টমেন্ট ডেট প্রয়োজন
		return acc.AppointmentDate == ""
	case 10:
		return acc.ReserveToken == ""
	case 11:
		return acc.ReservationID == ""
	case 12:
		return acc.PayToken == ""
	case 13:
		return acc.PaymentLink == ""
	}
	return false
}

func buildSteps(acc *Account, startStep int) []int {
	var steps []int
	allSteps := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}

	if startStep == 0 {
		// startStep 0 হলে সব স্টেপ চেক করে
		for _, step := range allSteps {
			if dataMissing(acc, step) {
				steps = append(steps, step)
			}
		}
		return steps
	}

	// startStep > 0 হলে শুধু startStep থেকে শুরু করে বাকি স্টেপগুলো যোগ করবে
	for _, step := range allSteps {
		if step >= startStep {
			steps = append(steps, step)
		}
	}
	return steps
}

func runAutomation(accountID string, startStep int) {
	log.Printf("[AUTO] ===== Starting automation for account %s from step %d =====", accountID, startStep)
	stopAutomation(accountID)
	ctx, cancel := context.WithCancel(context.Background())
	tasksMu.Lock()
	runningTasks[accountID] = cancel
	tasksMu.Unlock()

	defer func() {
		tasksMu.Lock()
		delete(runningTasks, accountID)
		tasksMu.Unlock()
		cancel()
		log.Printf("[AUTO] Cleanup done for account %s", accountID)
	}()

	acc := storage.GetAccount(accountID)
	if acc == nil {
		log.Printf("[AUTO] ❌ Account %s not found", accountID)
		storage.UpdateAccountField(accountID, "status", "error")
		return
	}
	ip := acc.IP

	if getEnableWarmup() {
		log.Printf("[AUTO] Warmup enabled, pre-connecting for account %s", accountID)
		go warmUpConnection(ip)
	}

	steps := buildSteps(acc, startStep)
	log.Printf("[AUTO] Steps to execute: %v", steps)

	for _, step := range steps {
		select {
		case <-ctx.Done():
			storage.UpdateAccountField(accountID, "status", "stopped")
			return
		default:
		}
		acc = storage.GetAccount(accountID)
		if acc == nil {
			log.Printf("[AUTO] ❌ Account %s disappeared", accountID)
			return
		}

		switch step {
		case 1:
			log.Printf("[AUTO] Step 1: Fetching sign token")
			storage.UpdateAccountField(accountID, "status", "Looking Sign Token")
			signToken, err := fetchSignToken(ctx, acc.Phone, acc.IP)
			if err != nil {
				log.Printf("[AUTO] ❌ Sign token failed: %v", err)
				storage.UpdateAccountField(accountID, "status", "Sign Token Not found")
				return
			}
			storage.UpdateAccountField(accountID, "sign_token", signToken)
			log.Printf("[AUTO] ✅ Sign token received")

		case 2:
			log.Printf("[AUTO] Step 2: Signing in (dynamic with auth override)")
			storage.UpdateAccountField(accountID, "status", "Sign in")
			method, urlStr, headers, body, err := prepareRequestWithAuth(ctx, "/auth/", acc, nil, acc.SignToken)
			if err != nil {
				log.Printf("[AUTO] ❌ Failed to prepare sign-in request: %v", err)
				storage.UpdateAccountField(accountID, "status", "Sign In Failed")
				return
			}
			bodyStr := fmt.Sprintf(`{"phone":"%s","password":"%s","c":"%s"}`,
				acc.Phone, acc.Password, acc.SignToken)
			body = []byte(bodyStr)
			log.Printf("[DEBUG] Sign-in URL: %s", urlStr)
			//log.Printf("[DEBUG] Sign-in Headers: %v", headers)
			//log.Printf("[DEBUG] Sign-in Body: %s", string(body))
			resp, err := doRequestWithRetry(ctx, method, urlStr, body, headers, ip)
			if err != nil {
				log.Printf("[AUTO] ❌ Sign in failed: %v", err)
				storage.UpdateAccountField(accountID, "status", "Sign in failed")
				return
			}
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			log.Printf("[DEBUG] Sign-in response: %s", string(respBody))

			var result map[string]interface{}
			if err := json.Unmarshal(respBody, &result); err != nil {
				log.Printf("[AUTO] ❌ Failed to parse sign-in response: %v", err)
				storage.UpdateAccountField(accountID, "status", string(respBody))
				return
			}
			if code, ok := result["code"].(float64); ok && code != 2000 {
				msg, _ := result["message"].(string)
				log.Printf("[AUTO] ❌ Sign-in failed: %s", msg)
				storage.UpdateAccountField(accountID, "status", msg)
				return
			}
			data, ok := result["data"].(map[string]interface{})
			if !ok {
				log.Printf("[AUTO] ❌ Data not found in response")
				storage.UpdateAccountField(accountID, "status", "No Data in response")
				return
			}
			accessToken, _ := data["accessToken"].(string)
			requestId, _ := data["requestId"].(string)
			if accessToken == "" || requestId == "" {
				log.Printf("[AUTO] ❌ Missing accessToken or requestId")
				storage.UpdateAccountField(accountID, "status", "Missing accessToken or requestId")
				return
			}
			storage.UpdateAccountField(accountID, "access_token", accessToken)
			storage.UpdateAccountField(accountID, "request_id", requestId)
			log.Printf("[AUTO] ✅ Sign in successful (requestId: %s)", requestId)
			storage.UpdateAccountField(accountID, "status", "✅ Sign in successful")
		case 3:
			log.Printf("[AUTO] Step 3: Fetching OTP")
			storage.UpdateAccountField(accountID, "status", "Looking for otp")
			select {
			case <-ctx.Done():
				storage.UpdateAccountField(accountID, "status", "stopped")
				return
			case <-time.After(10 * time.Second):
			}
			otp, err := fetchOTP(ctx, acc.Phone, acc.IP)
			if err != nil {
				log.Printf("[AUTO] ❌ OTP fetch failed: %v", err)
				storage.UpdateAccountField(accountID, "status", "OTP fetch failed")
				return
			}
			storage.UpdateAccountField(accountID, "otp", otp)
			storage.UpdateAccountField(accountID, "otp_verified", "false")
			storage.UpdateAccountOTPFetchedAt(accountID, time.Now())
			log.Printf("[AUTO] ✅ OTP received: %s", otp)

		case 4:
			log.Printf("[AUTO] Step 4: Verifying OTP (dynamic)")
			storage.UpdateAccountField(accountID, "status", "Verifying otp")
			for {
				select {
				case <-ctx.Done():
					storage.UpdateAccountField(accountID, "status", "stopped")
					return
				default:
				}
				if storage.GetAccount(accountID) == nil {
					log.Printf("[AUTO] ⚠️ Account %s deleted mid-verification, stopping", accountID)
					return
				}
				otp := acc.OTP
				if otp == "" && !acc.OTPVerified {
					log.Printf("[AUTO] OTP empty, fetching before verify")
					var err error
					otp, err = fetchOTP(ctx, acc.Phone, acc.IP)
					if err != nil {
						log.Printf("[AUTO] ❌ OTP fetch failed: %v, retrying in 5s...", err)
						time.Sleep(5 * time.Second)
						continue
					}
					storage.UpdateAccountField(accountID, "otp", otp)
					storage.UpdateAccountField(accountID, "otp_verified", "false")
					storage.UpdateAccountOTPFetchedAt(accountID, time.Now())
					log.Printf("[AUTO] ✅ OTP fetched: %s", otp)
				}
				method, urlStr, headers, body, err := prepareRequestWithAuth(ctx, "/otp/", acc, map[string]string{"OTP": otp}, acc.AccessToken)
				if err != nil {
					log.Printf("[AUTO] ❌ Failed to prepare verify OTP request: %v", err)
					time.Sleep(5 * time.Second)
					continue
				}
				bodyStr := fmt.Sprintf(`{"requestId":"%s","phone":"%s","code":"%s","otpChannel":"PHONE"}`,
					acc.RequestID, acc.Phone, otp)
				body = []byte(bodyStr)
				resp, err := doRequestWithRetry(ctx, method, urlStr, body, headers, ip)
				if err != nil {
					log.Printf("[AUTO] ❌ Verify OTP request failed: %v", err)
					time.Sleep(5 * time.Second)
					continue
				}
				respBody, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				log.Printf("[DEBUG] Verify OTP response: %s", string(respBody))
				var result map[string]interface{}
				if err := json.Unmarshal(respBody, &result); err != nil {
					log.Printf("[AUTO] ❌ Failed to parse verify OTP response: %v", err)
					time.Sleep(5 * time.Second)
					continue
				}
				if code, ok := result["code"].(float64); ok && code == 2000 {
					log.Printf("[AUTO] ✅ OTP verified successfully")
					storage.UpdateAccountField(accountID, "otp_verified", "true")
					storage.UpdateAccountField(accountID, "status", "✅ OTP verified")
					go clearOTPFromServer(ctx, acc.Phone, acc.IP)
					break
				}
				if success, ok := result["successFlag"].(bool); ok && success {
					log.Printf("[AUTO] ✅ OTP verification succeeded")
					storage.UpdateAccountField(accountID, "otp_verified", "true")
					storage.UpdateAccountField(accountID, "status", "✅ OTP verified")
					go clearOTPFromServer(ctx, acc.Phone, acc.IP)
					break
				} else {
					log.Printf("[AUTO] ❌ OTP verification failed, retrying...")
					storage.UpdateAccountField(accountID, "otp", "")
					storage.UpdateAccountField(accountID, "otp_verified", "false")
					storage.UpdateAccountField(accountID, "status", "❌ OTP verification failed")
					go clearOTPFromServer(ctx, acc.Phone, acc.IP)
					time.Sleep(5 * time.Second)
					continue
				}
				break
			}

		case 5:
			log.Printf("[AUTO] Step 5: File confirmation (dynamic)")
			storage.UpdateAccountField(accountID, "status", "file confirmation")
			method, urlStr, headers, body, err := prepareRequestWithAuth(ctx, "status", acc, nil, acc.AccessToken)
			if err != nil {
				log.Printf("[AUTO] ❌ Failed to prepare confirmation request: %v", err)
				storage.UpdateAccountField(accountID, "status", "failed")
				return
			}
			resp, err := doRequestWithRetry(ctx, method, urlStr, body, headers, ip)
			if err != nil {
				log.Printf("[AUTO] ❌ File confirmation failed: %v", err)
				storage.UpdateAccountField(accountID, "status", "File confirmation failed.")
				return
			}
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			log.Printf("[DEBUG] Confirmation response: %s", string(respBody))

			var result map[string]interface{}
			if err := json.Unmarshal(respBody, &result); err == nil {
				if data, ok := result["data"].(map[string]interface{}); ok {
					// Confirmation ID
					if cid, ok := data["confirmationId"].(string); ok && cid != "" {
						storage.UpdateAccountField(accountID, "confirmation_id", cid)
						log.Printf("[AUTO] ✅ Confirmation ID: %s", cid)
					}

					// ★★★ FileUploadConfirmed সংরক্ষণ ★★★
					if fileUploadConfirmed, ok := data["fileUploadConfirmed"].(bool); ok {
						storage.mu.Lock()
						for i := range storage.Accounts {
							if storage.Accounts[i].ID == accountID {
								storage.Accounts[i].FileUploadConfirmed = fileUploadConfirmed
								storage.saveLocked()
								break
							}
						}
						storage.mu.Unlock()
						log.Printf("[AUTO] File upload confirmed status: %v", fileUploadConfirmed)
					}

					// অন্যান্য ফ্ল্যাগ (প্রয়োজনে)
					if uploadEnd, ok := data["uploadEnd"].(bool); ok {
						storage.mu.Lock()
						for i := range storage.Accounts {
							if storage.Accounts[i].ID == accountID {
								storage.Accounts[i].UploadEnd = uploadEnd
								storage.saveLocked()
								break
							}
						}
						storage.mu.Unlock()
					}
				}
			}

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				storage.UpdateAccountField(accountID, "status", "File confirmation successful")
				log.Printf("[AUTO] ✅ File confirmation successful")
			} else {
				log.Printf("[AUTO] ❌ File confirmation HTTP error: %d", resp.StatusCode)
				storage.UpdateAccountField(accountID, "status", "File confirmation HTTP error")
				return
			}

		case 6:
			log.Printf("[AUTO] Step 6: Appointment (hardcoded URL)")
			storage.UpdateAccountField(accountID, "status", "Appointment")

			urlStr := "https://api.ivacbd.com/iams/api/v1/appointment"
			method := "POST"
			headers := map[string]string{
				"Accept":        "application/json, text/plain, */*",
				"Cache-Control": "no-cache, no-store, must-revalidate",
				"Pragma":        "no-cache",
				"Authorization": "Bearer " + acc.AccessToken,
				"User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			}
			// ★★★ NEW — dynamic sec headers ★★★
			injectSecurityHeaders(ctx, headers)

			resp, err := doRequestWithRetry(ctx, method, urlStr, nil, headers, ip)
			if err != nil {
				log.Printf("[AUTO] ❌ Appointment request failed: %v", err)
				storage.UpdateAccountField(accountID, "status", "Appointment request failed.")
				return
			}
			defer resp.Body.Close()

			// ★★ শুধু status code চেক করুন ★★
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				log.Printf("[AUTO] ✅ Appointment successful (status %d)", resp.StatusCode)
				storage.UpdateAccountField(accountID, "status", "Appointment successful")
				// কন্টেন্ট পড়ার প্রয়োজন নেই, পরবর্তী স্টেপে যান
			} else {
				log.Printf("[AUTO] ❌ Appointment HTTP error: %d", resp.StatusCode)
				storage.UpdateAccountField(accountID, "status", "Appointment failed")
				return
			}

		case 7:
			log.Printf("[AUTO] Step 7: File Upload (multipart/form-data) - Concurrent mode")

			acc = storage.GetAccount(accountID)
			if acc == nil {
				log.Printf("[AUTO] ❌ Account disappeared")
				return
			}

			// FileUploadConfirmed চেক করুন
			if acc.FileUploadConfirmed && len(acc.UploadFiles) > 0 {
				log.Printf("[AUTO] ⏭️ File already uploaded and confirmed, skipping upload")
				storage.UpdateAccountField(accountID, "status", "file already uploaded and confirmed, skipping upload")
				continue
			}

			if len(acc.UploadFiles) == 0 {
				log.Printf("[AUTO] No files to upload, skipping")
				storage.UpdateAccountField(accountID, "status", "No files to upload, skipping")
				continue
			}

			// UploadedFiles ম্যাপ তৈরি করুন
			uploadedMap := make(map[string]bool)
			for _, f := range acc.UploadedFiles {
				uploadedMap[f] = true
			}

			// বাকি ফাইল বের করুন
			var pendingFiles []string
			for _, f := range acc.UploadFiles {
				if !uploadedMap[f] {
					pendingFiles = append(pendingFiles, f)
				}
			}

			if len(pendingFiles) == 0 {
				log.Printf("[AUTO] ✅ All files already uploaded")
				storage.UpdateAccountField(accountID, "status", "all files uploaded")
				continue
			}

			log.Printf("[AUTO] Pending files to upload: %v", pendingFiles)

			// ফাইল সাজানো (প্রাইমারি প্রথমে)
			sort.Slice(pendingFiles, func(i, j int) bool {
				isPrimaryI := strings.HasPrefix(pendingFiles[i], "primary_")
				isPrimaryJ := strings.HasPrefix(pendingFiles[j], "primary_")
				if isPrimaryI && !isPrimaryJ {
					return true
				}
				if !isPrimaryI && isPrimaryJ {
					return false
				}
				return pendingFiles[i] < pendingFiles[j]
			})

			// এন্ডপয়েন্ট ও বেস হেডার ফেচ
			method, urlStr, headers, _, err := fetchEndpoint("file/up")
			if err != nil {
				log.Printf("[AUTO] ❌ Failed to fetch upload endpoint: %v", err)
				storage.UpdateAccountField(accountID, "status", "Failed to fetch upload endpoint")
				return
			}
			if !strings.HasPrefix(urlStr, "http") {
				urlStr = "https://api.ivacbd.com" + urlStr
			}
			log.Printf("[DEBUG] Upload URL: %s", urlStr)

			baseHeaders := map[string]string{}
			for k, v := range headers {
				if strings.ToLower(k) == "content-type" {
					continue
				}
				baseHeaders[k] = replacePlaceholders(v, acc, nil)
			}
			baseHeaders["Authorization"] = "Bearer " + acc.AccessToken

			// ★★★ NEW — dynamic sec headers inject (hardcoded fallback সরিয়ে) ★★★
			injectSecurityHeaders(ctx, baseHeaders)

			baseHeaders["Accept"] = "application/json, text/plain, */*"
			baseHeaders["Cache-Control"] = "no-cache, no-store, must-revalidate"
			baseHeaders["Pragma"] = "no-cache"

			// ============================================================
			// ★★★ Concurrent Upload - Primary ফাইল আলাদা, বাকি files একসাথে ★★★
			// ============================================================

			var primaryFile string
			var secondaryFiles []string

			// প্রাইমারি এবং সেকেন্ডারি ফাইল আলাদা করুন
			for _, f := range pendingFiles {
				if strings.HasPrefix(f, "primary_") {
					primaryFile = f
				} else {
					secondaryFiles = append(secondaryFiles, f)
				}
			}

			// ✅ প্রথমে Primary ফাইল আপলোড করুন (Sequential)
			if primaryFile != "" {
				log.Printf("[AUTO] 📤 Uploading PRIMARY file: %s", primaryFile)
				storage.UpdateAccountField(accountID, "status", "Uploading_primary")

				success := uploadSingleFile(ctx, accountID, method, urlStr, baseHeaders, primaryFile, true, acc.Phone, acc.IP)
				if !success {
					log.Printf("[AUTO] ❌ Primary file upload failed, will retry")
					storage.UpdateAccountField(accountID, "status", "primary_upload_failed")
					return
				}
				log.Printf("[AUTO] ✅ Primary file uploaded successfully")
			}

			// ✅ Secondary files একসাথে Concurrently আপলোড করুন
			if len(secondaryFiles) > 0 {
				log.Printf("[AUTO] 📤 Uploading %d SECONDARY files concurrently...", len(secondaryFiles))
				storage.UpdateAccountField(accountID, "status", fmt.Sprintf("uploading_%d_secondary", len(secondaryFiles)))

				// WaitGroup ব্যবহার করে Concurrently আপলোড করুন
				var wg sync.WaitGroup
				results := make(chan uploadResult, len(secondaryFiles))
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()

				for _, fileName := range secondaryFiles {
					wg.Add(1)
					go func(fname string) {
						defer wg.Done()
						success := uploadSingleFile(ctx, accountID, method, urlStr, baseHeaders, fname, false, acc.Phone, acc.IP)
						results <- uploadResult{filename: fname, success: success}
					}(fileName)
				}

				// সব goroutine শেষ হওয়া পর্যন্ত অপেক্ষা করুন
				go func() {
					wg.Wait()
					close(results)
				}()

				// ফলাফল সংগ্রহ করুন
				uploadSuccess := make(map[string]bool)
				allSuccess := true
				for result := range results {
					uploadSuccess[result.filename] = result.success
					if !result.success {
						allSuccess = false
						log.Printf("[AUTO] ❌ File %s upload failed", result.filename)
					} else {
						log.Printf("[AUTO] ✅ File %s uploaded successfully", result.filename)
					}
				}

				if allSuccess {
					storage.UpdateAccountField(accountID, "status", "✅ All secondary files uploaded successfully")
					log.Printf("[AUTO] ✅ All secondary files uploaded successfully")
				} else {
					storage.UpdateAccountField(accountID, "status", "secondary_upload_retry")
					log.Printf("[AUTO] ⚠️ Some secondary files failed, will retry in next cycle")
					return
				}
			}

			// সব ফাইল আপলোড হয়েছে কিনা চেক করুন
			acc = storage.GetAccount(accountID)
			if acc == nil {
				log.Printf("[AUTO] ❌ Account disappeared")
				return
			}

			// সব ফাইল আপলোড হয়েছে কিনা যাচাই করুন
			allUploaded := true
			uploadedMap2 := make(map[string]bool)
			for _, f := range acc.UploadedFiles {
				uploadedMap2[f] = true
			}
			for _, f := range acc.UploadFiles {
				if !uploadedMap2[f] {
					allUploaded = false
					break
				}
			}

			if allUploaded {
				// ★★★ FileUploadConfirmed = true সেট করুন ★★★
				storage.mu.Lock()
				for i := range storage.Accounts {
					if storage.Accounts[i].ID == accountID {
						storage.Accounts[i].FileUploadConfirmed = false
						storage.saveLocked()
						break
					}
				}
				storage.mu.Unlock()

				storage.UpdateAccountField(accountID, "status", "✅ All files uploaded successfully")
				log.Printf("[AUTO] ✅ All files uploaded successfully")
				// ★★★ return করবেন না, পরবর্তী স্টেপে যান ★★★
			} else {
				storage.UpdateAccountField(accountID, "status", "upload_retry")
				log.Printf("[AUTO] ⚠️ Some files still pending, will retry in next cycle")
				return
			}
		case 8:
			log.Printf("[AUTO] Step 8: Mission Submit (dynamic)")

			acc = storage.GetAccount(accountID)
			if acc == nil {
				log.Printf("[AUTO] ❌ Account disappeared")
				return
			}

			// ★★★ FileUploadConfirmed true হলে স্কিপ (ইতিমধ্যে কনফার্ম হয়ে গেছে) ★★★
			if acc.FileUploadConfirmed {
				log.Printf("[AUTO] ⏭️ File already confirmed, skipping mission submit")
				storage.UpdateAccountField(accountID, "status", "mission_skipped")
				continue
			}

			storage.UpdateAccountField(accountID, "status", "mission submit")

			method, urlStr, headers, _, err := fetchEndpoint("nt-booking")
			if err != nil {
				log.Printf("[AUTO] ❌ Failed to fetch mission endpoint: %v", err)
				storage.UpdateAccountField(accountID, "status", "Failed to fetch mission endpoint")
				return
			}
			if !strings.HasPrefix(urlStr, "http") {
				urlStr = "https://api.ivacbd.com" + urlStr
			}
			log.Printf("[DEBUG] Mission URL: %s", urlStr)

			reqHeaders := map[string]string{}
			for k, v := range headers {
				if strings.ToLower(k) == "content-type" {
					continue
				}
				reqHeaders[k] = replacePlaceholders(v, acc, nil)
			}
			reqHeaders["Authorization"] = "Bearer " + acc.AccessToken
			reqHeaders["Content-Type"] = "application/json"
			injectSecurityHeaders(ctx, reqHeaders)
			bodyMap := map[string]string{
				"mission":    acc.Mission,
				"ivacCenter": acc.IvacCenter,
			}
			jsonBody, err := json.Marshal(bodyMap)
			if err != nil {
				log.Printf("[AUTO] ❌ Failed to marshal mission body: %v", err)
				storage.UpdateAccountField(accountID, "status", "Failed to marshal mission body")
				return
			}
			log.Printf("[DEBUG] Mission body: %s", string(jsonBody))

			resp, err := doRequestWithRetry(ctx, method, urlStr, jsonBody, reqHeaders, ip)
			if err != nil {
				log.Printf("[AUTO] ❌ Mission request failed: %v", err)
				storage.UpdateAccountField(accountID, "status", "Mission request failed")
				return
			}
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			log.Printf("[DEBUG] Mission submit response: %s", string(respBody))

			var result map[string]interface{}
			if err := json.Unmarshal(respBody, &result); err == nil {
				if data, ok := result["data"].(map[string]interface{}); ok {
					if mid, ok := data["missionId"].(string); ok && mid != "" {
						storage.UpdateAccountField(accountID, "mission_id", mid)
						log.Printf("[AUTO] ✅ Mission ID: %s", mid)
					}
				}
			}

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				// ★★★ মিশন সাবমিট সফল হলে FileUploadConfirmed = true ★★★
				storage.mu.Lock()
				for i := range storage.Accounts {
					if storage.Accounts[i].ID == accountID {
						storage.Accounts[i].FileUploadConfirmed = true
						storage.saveLocked()
						break
					}
				}
				storage.mu.Unlock()

				storage.UpdateAccountField(accountID, "status", "mission submitted")
				log.Printf("[AUTO] ✅ Mission submitted successfully - File upload confirmed!")
			} else {
				log.Printf("[AUTO] ❌ Mission submit HTTP error: %d", resp.StatusCode)
				storage.UpdateAccountField(accountID, "status", "mission_failed")
				// ★★★ মিশন ফেল করলে FileUploadConfirmed false থাকবে ★★★
				return
			}
		case 9:
			log.Printf("[AUTO] Step 9: Get Booking Config (dynamic)")
			storage.UpdateAccountField(accountID, "status", "getting booking config")

			method, urlStr, headers, body, err := prepareRequestWithAuth(ctx, "et-booking", acc, nil, acc.AccessToken)
			if err != nil {
				log.Printf("[AUTO] ❌ Failed to prepare get booking config request: %v", err)
				storage.UpdateAccountField(accountID, "status", "Failed to prepare get booking config request")
				return
			}
			resp, err := doRequestWithRetry(ctx, method, urlStr, body, headers, ip)
			if err != nil {
				log.Printf("[AUTO] ❌ Get booking config failed: %v", err)
				storage.UpdateAccountField(accountID, "status", "Get booking config failed")
				return
			}
			defer resp.Body.Close()
			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Printf("[AUTO] ❌ Failed to read get-booking-config response body: %v", err)
				storage.UpdateAccountField(accountID, "status", "Failed to read get-booking-config response")
				return
			}
			log.Printf("[DEBUG] Get booking config response (status %d): %s", resp.StatusCode, string(respBody))

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				log.Printf("[AUTO] ❌ Get booking config HTTP error: %d", resp.StatusCode)
				storage.UpdateAccountField(accountID, "status", "Get booking config HTTP Error")
				return
			}

			var result map[string]interface{}
			if err := json.Unmarshal(respBody, &result); err != nil {
				log.Printf("[AUTO] ❌ Failed to parse get-booking-config response: %v", err)
				storage.UpdateAccountField(accountID, "status", "Failed to parse get-booking-config response")
				return
			}

			data, ok := result["data"].(map[string]interface{})
			if !ok {
				log.Printf("[AUTO] ❌ Data not found in get-booking-config response")
				storage.UpdateAccountField(accountID, "status", "Data not found in get-booking-config response")
				return
			}

			// ★★★ appointmentId এক্সট্রাক্ট করুন ★★★
			var appID string
			if aptID, ok := data["appointmentId"].(string); ok && aptID != "" {
				appID = aptID
				log.Printf("[AUTO] ✅ Appointment ID from booking config: %s", appID)
			} else if aptID, ok := data["appointment_id"].(string); ok && aptID != "" {
				appID = aptID
				log.Printf("[AUTO] ✅ Appointment ID from booking config: %s", appID)
			}

			// ★★★ appointmentId সংরক্ষণ করুন ★★★
			if appID != "" {
				storage.UpdateAccountField(accountID, "appointment_id", appID)
				log.Printf("[AUTO] ✅ Appointment ID saved: %s", appID)
			} else {
				log.Printf("[AUTO] ⚠️ No appointment ID found in booking config")
			}

			// ★★★ appointmentDate পার্স করুন ★★★
			var appDates []string
			switch v := data["appointmentDate"].(type) {
			case string:
				if v != "" {
					appDates = append(appDates, v)
				}
			case []interface{}:
				for _, item := range v {
					if s, ok := item.(string); ok && s != "" {
						appDates = append(appDates, s)
					}
				}
			case []string:
				appDates = v
			}

			if len(appDates) > 0 {
				for i, j := 0, len(appDates)-1; i < j; i, j = i+1, j-1 {
					appDates[i], appDates[j] = appDates[j], appDates[i]
				}
				storage.mu.Lock()
				for i := range storage.Accounts {
					if storage.Accounts[i].ID == accountID {
						storage.Accounts[i].AppointmentDates = appDates
						storage.Accounts[i].AppointmentDate = appDates[0]
						storage.saveLocked()
						break
					}
				}
				storage.mu.Unlock()
				log.Printf("[AUTO] ✅ Appointment Dates updated: %v", appDates)
			} else {
				log.Printf("[AUTO] ⚠️ No appointment date found in booking config response")
			}

			storage.UpdateAccountField(accountID, "status", "booking config fetched")
			log.Printf("[AUTO] ✅ Booking config fetched")

		case 10:
			log.Printf("[AUTO] Step 10: Fetching reserve token")
			storage.UpdateAccountField(accountID, "status", "Reserve token..")
			reserveToken, err := fetchReserveToken(ctx, acc.Phone, acc.IP)
			if err != nil {
				log.Printf("[AUTO] ❌ Reserve token failed: %v", err)
				storage.UpdateAccountField(accountID, "status", "No reserve Token")
				return
			}
			storage.UpdateAccountField(accountID, "reserve_token", reserveToken)
			log.Printf("[AUTO] ✅ Reserve token received")

		case 11:
			log.Printf("[AUTO] Step 11: Reserving slot (dynamic)")
			storage.UpdateAccountField(accountID, "status", "reserving slot")

			if storage.GetAccount(accountID) == nil {
				log.Printf("[AUTO] ⚠️ Account %s deleted mid-reserve, stopping", accountID)
				return
			}

			// ★ ফেচ সার্ভার থেকে URL নিন ★
			method, urlStr, headers, _, err := fetchEndpoint("/slots/")
			if err != nil {
				log.Printf("[AUTO] ❌ Failed to fetch reserve-slot endpoint: %v", err)
				storage.UpdateAccountField(accountID, "status", "Failed to fetch reserve-slot endpoint")
				return
			}

			if !strings.HasPrefix(urlStr, "http") {
				urlStr = "https://api.ivacbd.com" + urlStr
			}

			log.Printf("[DEBUG] Reserve URL from fetch server: %s", urlStr)

			reqHeaders := map[string]string{}
			for k, v := range headers {
				if strings.ToLower(k) == "content-type" {
					continue
				}
				reqHeaders[k] = v
			}
			reqHeaders["Authorization"] = "Bearer " + acc.AccessToken
			reqHeaders["Content-Type"] = "application/json"
			reqHeaders["x-v-request-meta"] = "windos.s"

			dates := acc.AppointmentDates
			if len(dates) == 0 {
				if acc.AppointmentDate != "" {
					dates = []string{acc.AppointmentDate}
				} else {
					log.Printf("[AUTO] ⚠️ No appointment dates available")
					storage.UpdateAccountField(accountID, "status", "failed - no dates")
					return
				}
			}

			reserveRetryDelay := getReserveRetryDelay()
			if reserveRetryDelay <= 0 {
				reserveRetryDelay = 20
			}

			var reservationID string
			dateIndex := 0
			maxAttempts := 30

			for attempt := 0; attempt < maxAttempts; attempt++ {
				reserveToken, err := fetchReserveToken(ctx, acc.Phone, acc.IP)
				if err != nil {
					log.Printf("[RESERVE] Failed to fetch reserve token: %v", err)
					dateIndex++
					time.Sleep(2 * time.Second)
					continue
				}
				log.Printf("[RESERVE] New reserve token fetched")

				date := dates[dateIndex%len(dates)]
				log.Printf("[RESERVE] Attempt %d: trying date %s", attempt+1, date)

				bodyMap := map[string]string{
					"c":               reserveToken,
					"appointmentDate": date,
				}
				jsonBody, err := json.Marshal(bodyMap)
				if err != nil {
					log.Printf("[RESERVE] Failed to marshal body: %v", err)
					dateIndex++
					time.Sleep(2 * time.Second)
					continue
				}
				log.Printf("[DEBUG] Reserve body: %s", string(jsonBody))

				resp, err := doRequestWithRetry(ctx, method, urlStr, jsonBody, reqHeaders, ip, 1)
				if err != nil {
					log.Printf("[RESERVE] Request failed: %v", err)
					dateIndex++
					time.Sleep(2 * time.Second)
					continue
				}
				respBody, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				log.Printf("[RESERVE] Response (date %s): %s", date, string(respBody))

				var result map[string]interface{}
				if err := json.Unmarshal(respBody, &result); err != nil {
					log.Printf("[RESERVE] JSON parse error: %v", err)
					dateIndex++
					time.Sleep(2 * time.Second)
					continue
				}

				if resID, ok := result["reservationId"].(string); ok && resID != "" {
					reservationID = resID
					log.Printf("[RESERVE] ✅ Reservation successful: %s", reservationID)

					// ★★★ যদি appointmentId পাওয়া যায় তাহলে সেটাও সেভ করুন ★★★
					if data, ok := result["data"].(map[string]interface{}); ok {
						if aptID, ok := data["appointmentId"].(string); ok && aptID != "" {
							storage.UpdateAccountField(accountID, "appointment_id", aptID)
							log.Printf("[RESERVE] ✅ Appointment ID from reserve response: %s", aptID)
						}
					}
					if aptID, ok := result["appointmentId"].(string); ok && aptID != "" {
						storage.UpdateAccountField(accountID, "appointment_id", aptID)
						log.Printf("[RESERVE] ✅ Appointment ID from reserve response: %s", aptID)
					}

					break
				}

				msg, _ := result["message"].(string)
				status, _ := result["status"].(string)
				if strings.Contains(strings.ToLower(msg), "completely booked") || status == "FULL" {
					storage.UpdateAccountField(accountID, "status", "Slot full")
					log.Printf("[RESERVE] Date %s completely booked, moving to next", date)
					dateIndex++
					time.Sleep(20 * time.Second)
					continue
				}

				log.Printf("[RESERVE] Unexpected response, moving to next date")
				dateIndex++
				time.Sleep(20 * time.Second)
			}

			if reservationID == "" {
				log.Printf("[AUTO] ❌ Reservation failed after %d attempts", maxAttempts)
				storage.UpdateAccountField(accountID, "status", "Reservation retry max")
				return
			}

			storage.UpdateAccountField(accountID, "reservation_id", reservationID)
			storage.UpdateAccountField(accountID, "status", "reserved")
			log.Printf("[AUTO] ✅ Reservation completed with Reservation ID: %s", reservationID)

		case 12:
			log.Printf("[AUTO] Step 12: Fetching pay token")
			storage.UpdateAccountField(accountID, "status", "Fetching pay token")
			payToken, err := fetchPayToken(ctx, acc.Phone, acc.IP)
			if err != nil {
				log.Printf("[AUTO] ❌ Pay token failed: %v", err)
				storage.UpdateAccountField(accountID, "status", "Pay token failed")
				return
			}
			storage.UpdateAccountField(accountID, "pay_token", payToken)
			log.Printf("[AUTO] ✅ Pay token received")

		case 13:
			log.Printf("[AUTO] Step 13: Initiating payment (dynamic)")
			storage.UpdateAccountField(accountID, "status", "initiating payment")

			acc = storage.GetAccount(accountID)
			if acc == nil {
				log.Printf("[AUTO] ❌ Account disappeared")
				return
			}

			// ★★★ appointmentId চেক করুন ★★★
			if acc.AppointmentID == "" {
				log.Printf("[AUTO] ⚠️ No appointment ID found, fetching from booking config...")

				// ★ বুকিং কনফিগ (স্টেপ ৯) কল করুন ★
				method, urlStr, headers, body, err := prepareRequestWithAuth(ctx, "et-booking", acc, nil, acc.AccessToken)
				if err != nil {
					log.Printf("[AUTO] ❌ Failed to prepare booking config request: %v", err)
					storage.UpdateAccountField(accountID, "status", "Failed to prepare booking config request")
					return
				}

				resp, err := doRequestWithRetry(ctx, method, urlStr, body, headers, ip)
				if err != nil {
					log.Printf("[AUTO] ❌ Booking config request failed: %v", err)
					storage.UpdateAccountField(accountID, "status", "Booking config request failed")
					return
				}

				respBody, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				log.Printf("[DEBUG] Booking config response: %s", string(respBody))

				var result map[string]interface{}
				if err := json.Unmarshal(respBody, &result); err != nil {
					log.Printf("[AUTO] ❌ Failed to parse booking config response: %v", err)
					storage.UpdateAccountField(accountID, "status", "Failed to parse booking config response")
					return
				}

				// appointmentId এক্সট্রাক্ট করুন
				var appID string
				if data, ok := result["data"].(map[string]interface{}); ok {
					if aptID, ok := data["appointmentId"].(string); ok && aptID != "" {
						appID = aptID
					} else if aptID, ok := data["appointment_id"].(string); ok && aptID != "" {
						appID = aptID
					}
				}

				if appID == "" {
					if aptID, ok := result["appointmentId"].(string); ok && aptID != "" {
						appID = aptID
					}
				}

				if appID == "" {
					log.Printf("[AUTO] ❌ No appointment ID found in booking config")
					storage.UpdateAccountField(accountID, "status", "no_appointment_id")
					return
				}

				// ★★★ appointmentId সংরক্ষণ করুন ★★★
				storage.UpdateAccountField(accountID, "appointment_id", appID)
				log.Printf("[AUTO] ✅ Appointment ID fetched and saved: %s", appID)

				// ★★★ appointmentDate ও আপডেট করুন ★★★
				if data, ok := result["data"].(map[string]interface{}); ok {
					var appDates []string
					switch v := data["appointmentDate"].(type) {
					case string:
						if v != "" {
							appDates = append(appDates, v)
						}
					case []interface{}:
						for _, item := range v {
							if s, ok := item.(string); ok && s != "" {
								appDates = append(appDates, s)
							}
						}
					case []string:
						appDates = v
					}

					if len(appDates) > 0 {
						storage.mu.Lock()
						for i := range storage.Accounts {
							if storage.Accounts[i].ID == accountID {
								storage.Accounts[i].AppointmentDates = appDates
								storage.Accounts[i].AppointmentDate = appDates[0]
								storage.saveLocked()
								break
							}
						}
						storage.mu.Unlock()
						log.Printf("[AUTO] ✅ Appointment Dates updated: %v", appDates)
					}
				}

				// অ্যাকাউন্ট রিলোড
				acc = storage.GetAccount(accountID)
				if acc == nil {
					log.Printf("[AUTO] ❌ Account disappeared")
					return
				}
			}

			// ★ এখন payment initiate করুন ★
			log.Printf("[AUTO] Initiating payment with Appointment ID: %s", acc.AppointmentID)

			method, urlStr, headers, _, err := fetchEndpoint("epay")
			if err != nil {
				log.Printf("[AUTO] ❌ Failed to fetch payment endpoint: %v", err)
				storage.UpdateAccountField(accountID, "status", "Failed to fetch payment endpoint")
				return
			}

			if !strings.HasPrefix(urlStr, "http") {
				urlStr = "https://api.ivacbd.com" + urlStr
			}
			log.Printf("[DEBUG] Payment URL from fetch server: %s", urlStr)

			reqHeaders := map[string]string{}
			for k, v := range headers {
				if strings.ToLower(k) == "content-type" {
					continue
				}
				reqHeaders[k] = v
			}
			reqHeaders["Authorization"] = "Bearer " + acc.AccessToken
			reqHeaders["Content-Type"] = "application/json"

			if acc.PayToken != "" {
				reqHeaders["x-token"] = acc.PayToken
			}

			bodyMap := map[string]string{
				"appointmentId": acc.AppointmentID,
			}

			jsonBody, err := json.Marshal(bodyMap)
			if err != nil {
				log.Printf("[AUTO] ❌ Failed to marshal payment body: %v", err)
				storage.UpdateAccountField(accountID, "status", "marshal payment body")
				return
			}
			log.Printf("[DEBUG] Payment body: %s", string(jsonBody))

			resp, err := doRequestWithRetry(ctx, method, urlStr, jsonBody, reqHeaders, ip)
			if err != nil {
				log.Printf("[AUTO] ❌ Initiate payment failed: %v", err)
				storage.UpdateAccountField(accountID, "status", "Initiate payment failed")
				return
			}
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			log.Printf("[DEBUG] Initiate payment response: %s", string(respBody))

			var result map[string]interface{}
			if err := json.Unmarshal(respBody, &result); err == nil {
				if data, ok := result["data"].(map[string]interface{}); ok {
					var paymentLink string
					if link, ok := data["webview_url"].(string); ok && link != "" {
						paymentLink = link
					} else if link, ok := data["gatewayUrl"].(string); ok && link != "" {
						paymentLink = link
					} else if link, ok := data["paymentUrl"].(string); ok && link != "" {
						paymentLink = link
					}

					if paymentLink != "" {
						storage.UpdateAccountField(accountID, "payment_link", paymentLink)
						storage.UpdateAccountPaymentLinkAt(accountID, time.Now())
						log.Printf("[AUTO] ✅ Payment link: %s", paymentLink)
					}
				}
			}

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				storage.UpdateAccountField(accountID, "status", "payment initiated")
				log.Printf("[AUTO] ✅ Payment initiated successfully")
			} else {
				log.Printf("[AUTO] ❌ Initiate payment HTTP error: %d", resp.StatusCode)
				storage.UpdateAccountField(accountID, "status", "payment_failed")
				return
			}
		} // ← switch step এর জন্য বন্ধনী
	} // ← for loop (steps) এর জন্য বন্ধনী

	// ★ সব স্টেপ শেষ হলে অ্যাকাউন্টের স্ট্যাটাস "completed" করুন
	storage.UpdateAccountField(accountID, "status", "completed")
	log.Printf("[AUTO] 🎉 Automation completed for account %s", accountID)
} // ← runAutomation ফাংশনের শেষ বন্ধনী

// ============================================================
// stopAutomation
// ============================================================

func stopAutomation(accountID string) {
	tasksMu.Lock()
	defer tasksMu.Unlock()

	if cancel, ok := runningTasks[accountID]; ok {
		cancel()
		delete(runningTasks, accountID)

		// ★★★ স্ট্যাটাস আপডেট - আলাদা goroutine এ ★★★
		go func(id string) {
			// টাস্ক থামার জন্য একটু অপেক্ষা
			time.Sleep(100 * time.Millisecond)

			// ★★★ শুধু মাত্র যদি স্ট্যাটাস "stopped" না হয় তাহলে আপডেট করুন ★★★
			acc := storage.GetAccount(id)
			if acc != nil && acc.Status != "completed" {
				storage.UpdateAccountField(id, "status", "stopped")
				log.Printf("[STOP] Stopped automation for account %s", id)
			}
		}(accountID)
	} else {
		log.Printf("[STOP] No running task found for account %s", accountID)
	}
}

// ============================================================
// ১২. ড্যাশবোর্ড হ্যান্ডলার (সম্পূর্ণ HTML)
// ============================================================

func jsEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "\\'")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

func adminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	isAdminUser := false
	if cookie, err := r.Cookie("token"); err == nil {
		if claims, err := validateToken(cookie.Value); err == nil && claims.Role == "admin" {
			isAdminUser = true
		}
	}
	if !isAdminUser {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
				claims, err := validateToken(parts[1])
				if err == nil && claims.Role == "admin" {
					isAdminUser = true
				}
			}
		}
	}

	storage.mu.Lock()
	retryCount := storage.Config.RetryCount
	retryDelay := storage.Config.RetryDelaySec
	concurrency := storage.Config.Concurrency
	signinConcurrency := storage.Config.SigninConcurrency
	delaySec := storage.Config.DelaySec
	reserveRetryDelay := storage.Config.ReserveRetryDelay
	enableRetry := storage.Config.EnableRetry
	tokenRetryCount := storage.Config.TokenRetryCount
	tokenRetryDelaySec := storage.Config.TokenRetryDelaySec
	tokenEnableRetry := storage.Config.TokenEnableRetry
	enableWarmup := storage.Config.EnableWarmup
	storage.mu.Unlock()

	enableRetryChecked := ""
	if enableRetry {
		enableRetryChecked = "checked"
	}
	tokenEnableRetryChecked := ""
	if tokenEnableRetry {
		tokenEnableRetryChecked = "checked"
	}
	enableWarmupChecked := ""
	if enableWarmup {
		enableWarmupChecked = "checked"
	}

	configBarHTML := ""
	if isAdminUser {
		configBarHTML = `<div class="config-bar">
			<div class="config-section">
				<span class="section-label">🔧 Main API</span>
				<label><span class="config-label">Enable Retry</span> <input type="checkbox" id="enable_retry" ` + enableRetryChecked + ` onchange="updateConfigField('enable_retry')"></label>
				<label><span class="config-label">Retry Count</span> <input type="number" id="retry_count" value="` + fmt.Sprint(retryCount) + `" min="0" max="500" onchange="updateConfigField('retry_count')"></label>
				<label><span class="config-label">Retry Delay (sec)</span> <input type="number" id="retry_delay_sec" value="` + fmt.Sprint(retryDelay) + `" min="0" max="500" onchange="updateConfigField('retry_delay_sec')"></label>
				<label><span class="config-label">Concurrency</span> <input type="number" id="concurrency" value="` + fmt.Sprint(concurrency) + `" min="0" max="20" onchange="updateConfigField('concurrency')"></label>
				<label><span class="config-label">Signin Concurrency</span> <input type="number" id="signin_concurrency" value="` + fmt.Sprint(signinConcurrency) + `" min="0" max="500" onchange="updateConfigField('signin_concurrency')"></label>
				<label><span class="config-label">Delay (sec)</span> <input type="number" id="delay_sec" value="` + fmt.Sprint(delaySec) + `" min="0" max="10" onchange="updateConfigField('delay_sec')"></label>
				<label><span class="config-label">Reserve Retry Delay (sec)</span> <input type="number" id="reserve_retry_delay" value="` + fmt.Sprint(reserveRetryDelay) + `" min="0" max="500" onchange="updateConfigField('reserve_retry_delay')"></label>
			</div>
			<div class="config-section" style="border-top:1px solid #444;padding-top:8px;">
				<span class="section-label">☁️ Token Service</span>
				<label><span class="token-label">Enable Retry</span> <input type="checkbox" id="token_enable_retry" ` + tokenEnableRetryChecked + ` onchange="updateConfigField('token_enable_retry')"></label>
				<label><span class="token-label">Retry Count</span> <input type="number" id="token_retry_count" value="` + fmt.Sprint(tokenRetryCount) + `" min="0" max="500" onchange="updateConfigField('token_retry_count')"></label>
				<label><span class="token-label">Retry Delay (sec)</span> <input type="number" id="token_retry_delay_sec" value="` + fmt.Sprint(tokenRetryDelaySec) + `" min="0" max="500" onchange="updateConfigField('token_retry_delay_sec')"></label>
			</div>
			<div class="config-section" style="border-top:1px solid #444;padding-top:8px;">
				<span class="section-label">🚀 Warmup</span>
				<label><span class="config-label">Enable Warmup</span> <input type="checkbox" id="enable_warmup" ` + enableWarmupChecked + ` onchange="updateConfigField('enable_warmup')"></label>
			</div>
			<span style="color:#888;font-size:12px;margin-left:5px;">(auto-save)</span>
		</div>`
	}

	html := `<!DOCTYPE html>
<html>
<head>
	<title>Hyp3r Panel v2</title>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">

	<style>
		* { margin:0; padding:0; box-sizing:border-box; }
		body { font-family: 'Segoe UI', sans-serif; background: #0a0a0f; color: #e0e0e0; padding: 20px; min-height: 100vh; }
		::-webkit-scrollbar { width: 6px; height: 6px; }
		::-webkit-scrollbar-track { background: #1a1a24; border-radius: 8px; }
		::-webkit-scrollbar-thumb { background: #3a3a4a; border-radius: 8px; }
		.header { display: flex; justify-content: space-between; align-items: center; padding: 16px 24px; background: linear-gradient(135deg, #12121c, #1a1a2e); border-radius: 16px; margin-bottom: 24px; border: 1px solid #2a2a3e; }
		.header h1 { font-size: 24px; font-weight: 700; background: linear-gradient(90deg, #00d4ff, #7b2ffc); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
		.header-actions { display: flex; gap: 12px; align-items: center; }
		.btn { padding: 8px 18px; border: none; border-radius: 10px; font-weight: 600; font-size: 15px; cursor: pointer; transition: all 0.25s ease; color: #fff; display: inline-flex; align-items: center; gap: 6px; text-decoration: none; }
		.btn:active { transform: scale(0.95); }
		.btn-start { background: linear-gradient(135deg, #00b894, #00a86b); }
		.btn-start:hover { box-shadow: 0 4px 20px rgba(0,184,148,0.4); }
		.btn-stop { background: linear-gradient(135deg, #ff6b6b, #e74c3c); }
		.btn-auto { background: linear-gradient(135deg, #fdcb6e, #f39c12); }
		.btn-delete { background: linear-gradient(135deg, #e17055, #d63031); }
		.btn-sm { padding: 4px 12px; font-size: 14px; border-radius: 6px; }
		.btn-logout { background: linear-gradient(135deg, #636e72, #2d3436); }
		.btn-restart { background: linear-gradient(135deg, #ff9f43, #ee5a24); }
		.btn-restart:hover { box-shadow: 0 4px 20px rgba(255,159,67,0.4); }
		.btn-restart.loading { opacity: 0.7; cursor: wait; }
		.btn-restart.loading::before { content: "⏳ "; }
		.extractor-status { display:inline-flex; align-items:center; gap:6px; padding:6px 12px; border-radius:8px; font-size:13px; font-weight:600; }
		.extractor-status.ok { background:rgba(0,184,148,0.2); color:#00b894; }
		.extractor-status.down { background:rgba(255,107,107,0.2); color:#ff6b6b; }
		.extractor-status.checking { background:rgba(253,203,110,0.2); color:#fdcb6e; }
		.extractor-status .dot { width:8px; height:8px; border-radius:50%; background:currentColor; }
		.btn-reset { background: linear-gradient(135deg, #fd79a8, #e84393); }
		.btn-pay { padding: 6px 18px; font-size: 16px; background: linear-gradient(135deg, #00b894, #00a86b); }
		.btn-upload { background: linear-gradient(135deg, #0984e3, #6c5ce7); }
		.btn-upload:hover { box-shadow: 0 4px 20px rgba(9,132,227,0.4); }
		.btn-danger { background: linear-gradient(135deg, #d63031, #c0392b); }
		.btn:disabled { opacity: 0.4; cursor: not-allowed; transform: none !important; }
		.tab-wrapper { background: #12121c; border-radius: 16px 16px 0 0; border: 1px solid #2a2a3e; border-bottom: none; padding: 0 20px; display: flex; gap: 4px; }
		.tab-btn { background: transparent; border: none; color: #888; padding: 14px 24px; font-size: 16px; font-weight: 600; cursor: pointer; border-bottom: 3px solid transparent; transition: all 0.3s ease; border-radius: 8px 8px 0 0; }
		.tab-btn:hover { color: #ccc; background: #1a1a2e; }
		.tab-btn.active { color: #00d4ff; border-bottom-color: #00d4ff; background: #1a1a2e; }
		.tab-content { display: none; background: #12121c; border: 1px solid #2a2a3e; border-top: none; border-radius: 0 0 16px 16px; padding: 20px; margin-bottom: 24px; }
		.tab-content.active { display: block; }
		.config-bar { display: flex; flex-wrap: wrap; align-items: center; gap: 12px 24px; background: #1a1a2e; padding: 14px 20px; border-radius: 12px; margin-bottom: 20px; border: 1px solid #2a2a3e; }
		.config-section { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 16px; }
		.config-section .section-label { color: #00d4ff; font-weight: 700; font-size: 13px; }
		.config-label { color: #aaa; font-size: 14px; }
		.token-label { color: #fdcb6e; font-size: 14px; }
		.config-bar label { display: flex; align-items: center; gap: 4px; font-size: 13px; }
		.config-bar input[type="number"] { width: 56px; background: #0a0a0f; border: 1px solid #333; color: #fff; padding: 4px 6px; border-radius: 6px; font-size: 12px; }
		.config-bar input[type="checkbox"] { width: 18px; height: 18px; accent-color: #00d4ff; cursor: pointer; }
		.form-container { background: #1a1a2e; border-radius: 12px; padding: 16px 20px; margin-bottom: 20px; border: 1px solid #2a2a3e; display: flex; flex-wrap: wrap; align-items: center; gap: 10px 14px; }
		.form-container h3 { font-size: 15px; font-weight: 600; color: #ccc; margin-right: 6px; }
		.form-container input, .form-container select { background: #0a0a0f; border: 1px solid #333; color: #fff; padding: 8px 12px; border-radius: 8px; font-size: 13px; min-width: 30px; }
		.form-container input:focus, .form-container select:focus { outline: none; border-color: #00d4ff; box-shadow: 0 0 0 3px rgba(0,212,255,0.15); }
		.table-wrap { overflow-x: auto; border-radius: 12px; border: 1px solid #2a2a3e; background: #0a0a0f; }
		table { width: 100%; border-collapse: collapse; font-size: 13px; min-width: 2200px; }
		th { background: #1a1a2e; color: #ccc; padding: 10px 12px; text-align: left; font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.3px; border-bottom: 2px solid #2a2a3e; position: sticky; top: 0; z-index: 10; white-space: nowrap; }
		td { padding: 8px 10px; border-bottom: 1px solid #1e1e2e; vertical-align: middle; word-break: break-word; }
		tr:hover td { background: #161624; }
		td input, td select { background: transparent; border: 1px solid transparent; color: #e0e0e0; padding: 4px 6px; border-radius: 4px; width: 100%; font-size: 12px; }
		td input:hover, td select:hover { border-color: #444; }
		td input:focus, td select:focus { outline: none; border-color: #00d4ff; background: #0a0a0f; }
		.account-checkbox{width:18px;height:18px;cursor:pointer;accent-color:#00d4ff;}
		#accountsBody tr{cursor:pointer;transition:background 0.2s ease;}
		#accountsBody tr:hover{background:#1a1a2e;}
		#accountsBody tr.selected{background:#1a2a3e;border-left:3px solid #00d4ff;}
		#accountsBody tr td input,#accountsBody tr td select,#accountsBody tr td button{cursor:default;}
		#accountsBody tr td input[type="checkbox"]{cursor:pointer;}
		.checkbox-wrapper{display:flex;align-items:center;justify-content:center;min-width:30px;min-height:30px;}
		.status-cell { font-weight: 600; text-transform: capitalize; }
		.status-idle { color: #888; }
		.status-fetching_token, .status-signing_in, .status-looking_for_otp, .status-verifying_otp, .status-reserve_token, .status-reserving_slot, .status-getting_appointment, .status-fetching_pay_token, .status-initiating_payment, .status-ready { color: #fdcb6e; }
		.status-completed { color: #00b894; }
		.status-error, .status-failed { color: #ff6b6b; font-weight: 700; }
		.status-stopped { color: #ff9f43; }
		.countdown { font-weight: 700; font-family: monospace; font-size: 13px; color: #00d4ff; }
		.token-cell { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
		.token-cell .token-trunc { font-family: monospace; font-size: 11px; color: #aaa; max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
		.btn-copy { background: transparent; border: none; color: #00d4ff; cursor: pointer; font-size: 16px; padding: 2px 6px; border-radius: 4px; transition: all 0.2s; }
		.btn-copy:hover { background: #1a2a3e; }
		.sign-token { font-size: 18px; text-align: center; }
		.file-list { display: flex; flex-direction: column; gap: 4px; }
		.file-item { display: flex; justify-content: space-between; align-items: center; background: #1a1a2e; padding: 4px 8px; border-radius: 4px; font-size: 12px; }
		.file-item .fname { max-width: 80px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
		.file-upload-form { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-top: 6px; }
		.file-upload-form input[type="file"] { color: #aaa; font-size: 12px; max-width: 120px; }
		.modal { display: none; position: fixed; z-index: 9999; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.8); backdrop-filter: blur(4px); }
		.modal-content { background: #1a1a2e; margin: 5% auto; padding: 20px; border: 1px solid #2a2a3e; border-radius: 16px; width: 90%; max-width: 550px; box-shadow: 0 24px 80px rgba(0,0,0,0.8); }
		.modal-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #333; padding-bottom: 12px; margin-bottom: 16px; }
		.modal-header h2 { font-size: 20px; color: #00d4ff; }
		.modal-close { background: none; border: none; color: #aaa; font-size: 28px; cursor: pointer; }
		.modal-close:hover { color: #fff; }
		.toast-container { position: fixed; top: 20px; right: 20px; z-index: 99999; display: flex; flex-direction: column; gap: 10px; max-width: 400px; width: 100%; pointer-events: none; }
		.toast { background: #1a1a2e; border: 1px solid #2a2a3e; border-radius: 12px; padding: 16px 20px; color: #e0e0e0; box-shadow: 0 12px 48px rgba(0,0,0,0.6); animation: slideIn 0.4s ease, fadeOut 0.4s ease 3.5s forwards; pointer-events: auto; display: flex; align-items: center; gap: 12px; }
		.toast.success { border-left: 4px solid #00b894; }
		.toast.error { border-left: 4px solid #ff6b6b; }
		.toast.info { border-left: 4px solid #00d4ff; }
		.toast .icon { font-size: 22px; }
		.toast .msg { font-size: 14px; font-weight: 500; flex: 1; }
		.toast .close { background: transparent; border: none; color: #888; cursor: pointer; font-size: 18px; padding: 0 4px; }
		.toast .close:hover { color: #fff; }
		@keyframes slideIn { from { opacity: 0; transform: translateX(60px); } to { opacity: 1; transform: translateX(0); } }
		@keyframes fadeOut { from { opacity: 1; transform: translateX(0); } to { opacity: 0; transform: translateX(60px); } }
		@media (max-width: 768px) { body { padding: 10px; } .header { flex-direction: column; gap: 12px; align-items: stretch; } .form-container { flex-direction: column; align-items: stretch; } .form-container input, .form-container select { width: 100%; min-width: unset; } .config-bar { flex-direction: column; align-items: stretch; } .config-section { flex-direction: column; align-items: stretch; } .tab-wrapper { overflow-x: auto; } .toast-container { max-width: 90%; right: 10px; top: 10px; } }
		#statusFilter:focus {
			outline: none;
			border-color: #00d4ff;
			box-shadow: 0 0 0 3px rgba(0,212,255,0.15);
		}

		/* ফিল্টার ইনপুট প্লেসহোল্ডার স্টাইল */
		#statusFilter::placeholder {
			color: #666;
			font-style: italic;
		}
		.pay-btn.paid {
			background: linear-gradient(135deg, #636e72, #2d3436) !important;
			color: #00b894 !important;
			border: 2px solid #00b894 !important;
			text-decoration: line-through;
			opacity: 0.7;
		}
		.pay-btn.paid::after {
			content: " ✅";
			text-decoration: none;
			display: inline-block;
		}
		.pay-btn.paid:hover {
			opacity: 0.9;
		}
	</style>
</head>
<body>
	<div id="toastContainer" class="toast-container"></div>
	<div class="header">
		<h1>⚡ Hyp3r Panel v2</h1>
		<div class="header-actions">
		<span id="extractorStatus" class="extractor-status checking">
			<span class="dot"></span>
			<span id="extractorStatusText">Checking...</span>
		</span>
			<button id="btnrestartExtractor" class="btn btn-restart" onclick="restartExtractor()">🔄 restart Extractor</button>
			<button class="btn btn-logout" onclick="logout()">🚪 Logout</button>
		</div>
	</div>
	<div class="tab-wrapper">
		<button class="tab-btn active" onclick="openTab(event,'accounts')">📋 Accounts</button>
		<button id="usersTabBtn" class="tab-btn" onclick="openTab(event,'users')" style="display:none;">👤 Users</button>
	</div>

	<div id="accounts" class="tab-content active">
		` + configBarHTML + `
		<div class="form-container">
			<h3>➕ Add Account</h3><br>
			<input type="text" id="phone" placeholder="Phone *">
			<input type="text" id="password" placeholder="Password *">
			<select id="userIdSelect" style="display:none;"><option value="">Select User</option></select>
			<select id="globalStepSelect" style="width:130px;">
				<option value="0">Start</option>
				<option value="1">Sign Token</option><option value="2">Signin</option><option value="3">Otp Read</option>
				<option value="4">Otp Verify</option><option value="5">Confirmation</option><option value="6">Appointment</option>
				<option value="7">Upload</option><option value="8">Mission</option><option value="9">Booking Config</option>
				<option value="10">Reserve Token</option><option value="11">Reserve</option><option value="12">Pay Token</option>
				<option value="13">Initiate</option>
			</select>
			<button class="btn btn-start" onclick="saveAccount()">💾 Save</button>
			<button class="btn btn-auto" onclick="autoAll()">🤖 Auto All</button>
			<button class="btn btn-auto" onclick="autoSelected()" style="background:linear-gradient(135deg, #a29bfe, #6c5ce7);">✅ Auto Selected</button> 
			<button class="btn btn-stop" onclick="stopSelected()" style="background:linear-gradient(135deg, #fd79a8, #e84393);">⏹ Stop Selected</button>
			<button class="btn btn-stop" onclick="stopAll()">⏹ Stop All</button>
			<button class="btn btn-delete" onclick="deleteAllAccounts()">🗑 Delete All</button>
			<button class="btn btn-reset" onclick="resetSelected()" style="background:linear-gradient(135deg, #fd79a8, #e84393);">🔄 Reset Selected</button>
		
				<!-- 🔍 ফিল্টার সেকশন - রিয়েল-টাইম -->
			<div style="display:flex; align-items:center; gap:10px; width:100%; margin-top:12px; border-top:1px solid #2a2a3e; padding-top:12px; flex-wrap:wrap;">
				<span style="color:#00d4ff; font-weight:600; font-size:14px;">🔍 Filter by Status:</span>
				<input type="text" id="statusFilter" placeholder="Type to filter... e.g. reserve, signin, completed" 
					style="flex:1; min-width:180px; background:#0a0a0f; border:1px solid #333; color:#fff; padding:8px 14px; border-radius:6px; font-size:13px; transition: border-color 0.3s ease;">
				<button class="btn btn-sm" onclick="clearFilter()" style="background:#636e72; padding:6px 16px;">✕ Clear</button>
				<span id="filterCount" style="color:#888; font-size:13px;"></span>
			</div>

		<div class="table-wrap">
			<table id="accountsTable">
				<thead id="accountsHead"></thead>
				<tbody id="accountsBody"></tbody>
			</table>
		</div>
	</div>
</div>
	<div id="users" class="tab-content">
		<div class="form-container">
			<h3>👤 Add User</h3>
			<input type="text" id="userUsername" placeholder="Username *">
			<input type="text" id="userPassword" placeholder="Password *">
			<select id="userRole"><option value="user">User</option><option value="admin">Admin</option></select>
			<button class="btn btn-start" onclick="addUser()">➕ Add</button>
		</div>
		<div class="table-wrap">
			<table><thead><tr><th>ID</th><th>Username</th><th>Role</th><th>Locked</th><th>Created</th><th>Actions</th></tr></thead>
			<tbody id="usersBody"></tbody></table>
		</div>
	</div>

	<!-- Modal -->
	<div id="fileModal" class="modal">
		<div class="modal-content">
			<div class="modal-header">
				<h2>📁 Manage Files & Mission</h2>
				<span class="modal-close" onclick="closeFileModal()">&times;</span>
			</div>
			<div id="fileModalBody">
				<p>Account: <strong id="modalAccountId"></strong></p>
				<div style="margin:10px 0;padding:10px;background:#1a1a2e;border-radius:8px;">
					<label style="display:block;margin-bottom:4px;font-weight:600;color:#00d4ff;">Select Mission:</label>
					<select id="modalMissionSelect" style="width:100%;padding:8px;background:#0a0a0f;border:1px solid #333;color:#fff;border-radius:6px;" onchange="updateMissionFromModal()">
						<option value="DHAKA">Dhaka</option>
						<option value="RAJSHAHI">Rajshahi</option>
						<option value="SYLHET">Sylhet</option>
						<option value="CHITTAGONG">Chittagong</option>
						<option value="KHULNA">khulna</option>
					</select>
				</div>
				<div id="fileListContainer"></div>
					<div id="dropZone" style="position:relative;border:2px dashed #444;padding:16px;border-radius:8px;text-align:center;cursor:pointer;transition:all 0.2s;background:transparent;min-height:90px;display:flex;align-items:center;justify-content:center;">
						<input type="file" id="fileInput" accept=".pdf" multiple style="display:none;">
						
						<!-- Normal content -->
						<div id="dropZoneContent" style="color:#888;font-size:13px;pointer-events:none;">
							<div style="font-size:28px;margin-bottom:6px;">📄</div>
							<div>Drag & drop PDF here</div>
							<div style="font-size:11px;margin-top:4px;">or click to select (max 10MB)</div>
						</div>
						
						<!-- Loading overlay -->
						<div id="dropZoneLoading" style="display:none;position:absolute;top:0;left:0;right:0;bottom:0;background:#1a1a2e;border-radius:6px;align-items:center;justify-content:center;flex-direction:column;color:#00d4ff;font-size:13px;gap:8px;">
							<div style="font-size:24px;">⏳</div>
							<div id="dropZoneProgressText">Uploading...</div>
							<div style="width:80%;max-width:250px;height:4px;background:#0a0a0f;border-radius:2px;overflow:hidden;">
								<div id="dropZoneProgressBar" style="height:100%;width:0%;background:linear-gradient(90deg,#00d4ff,#7b2ffc);transition:width 0.2s ease;"></div>
							</div>
						</div>
					</div>
				<p style="color:#888;font-size:12px;margin-top:8px;">Max 4 files, only PDF allowed.</p>
			</div>
		</div>
	</div>

	<script>
	var selectedAccounts = {};
		function showToast(msg, type, duration) {
			var c = document.getElementById('toastContainer');
			var icons = {success:'✅', error:'❌', info:'ℹ️'};
			var t = document.createElement('div');
			t.className = 'toast ' + type;
			t.innerHTML = '<span class="icon">'+(icons[type]||'ℹ️')+'</span><span class="msg">'+msg+'</span><button class="close" onclick="this.parentElement.remove()">✕</button>';
			c.appendChild(t);
			var dur = duration || 4000;
			setTimeout(function(){ if(t.parentElement) t.remove(); }, dur);
		}

		var token = localStorage.getItem('token');
		var role = localStorage.getItem('role');
		var locked = localStorage.getItem('locked') === 'true';
		var isAdmin = role === 'admin';
		if (!token) { window.location.href = '/login'; }
		var paidAccounts = {};

		var pollingInterval = null;
		function startPolling() { if(pollingInterval) clearInterval(pollingInterval); pollingInterval = setInterval(fetchAccounts, 5000); }
		function stopPolling() { if(pollingInterval) { clearInterval(pollingInterval); pollingInterval = null; } }

		if (isAdmin) {
			document.getElementById('usersTabBtn').style.display = 'inline-block';
			document.getElementById('userIdSelect').style.display = 'inline-block';
		} else {
			document.getElementById('globalStepSelect').disabled = true;
			document.querySelectorAll('.form-container .btn-auto, .form-container .btn-stop, .form-container .btn-delete').forEach(function(el){ el.disabled = true; });
			if (locked) document.querySelector('.form-container').style.display = 'none';
		}

		function esc(s) {
			if (!s) return '';
			return String(s).replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/'/g, "\\'");
		}
		function trunc(s,n){ return s && s.length>n ? s.substring(0,n)+'..' : (s||''); }
		function markPayClicked(el) {
			el.classList.add('paid');
			el.textContent = 'Paid';		
		}
		var MISSION_DATA = {
			"DHAKA": { mission: "Dhaka", ivacCenter: "IVAC, Dhaka (JFP)" },
			"RAJSHAHI": { mission: "Rajshahi", ivacCenter: "IVAC, RAJSHAHI" },
			"SYLHET": { mission: "Sylhet", ivacCenter: "IVAC, SYLHET" },
			"CHITTAGONG": { mission: "Chittagong", ivacCenter: "IVAC, CHITTAGONG" },
			"KHULNA": { mission: "khulna", ivacCenter: "IVAC, KHULNA" }
		};

		function copyToken(text,btn){
			if(!text) return;
			if (navigator.clipboard) {
				navigator.clipboard.writeText(text).then(function(){
					btn.textContent='✅';
					btn.classList.add('copied');
					showToast('Copied!','success');
					setTimeout(function(){ btn.textContent='📋'; btn.classList.remove('copied'); },2000);
				}).catch(function(){
					fallbackCopy(text, btn);
				});
			} else {
				fallbackCopy(text, btn);
			}
		}
		function fallbackCopy(text, btn){
			var ta=document.createElement('textarea');
			ta.value=text;
			document.body.appendChild(ta);
			ta.select();
			document.execCommand('copy');
			document.body.removeChild(ta);
			btn.textContent='✅';
			btn.classList.add('copied');
			showToast('Copied!','success');
			setTimeout(function(){ btn.textContent='📋'; btn.classList.remove('copied'); },2000);
		}

		function renderHeaders() {
			var thead = document.getElementById('accountsHead');
			var html = '<tr>';
			html += '<th><input type="checkbox" id="selectAll" onchange="toggleAllAccounts(this.checked)"></th>'; // ← নতুন
			html += '<th>SL</th>';
			if (isAdmin) {
				html += '<th>ID / User</th>';
			} else if (!locked) {
				html += '<th>ID</th>';
			}
			html += '<th>Phone / Password / Status</th><th>OTP</th>';
			html += '<th>AccessToken</th><th>ResvID</th><th>ApptID</th>';
			html += '<th>Mission / Ivac Center</th>';
			html += '<th>Payment</th><th>OTP Fetched</th><th>⏳ OTP Left</th><th>Pay Link At</th><th>⏳ Pay Left</th>';
			html += '<th>Files</th><th>Actions</th>';
			if (isAdmin) html += '<th>IP</th><th>Reset</th>';
			html += '</tr>';
			thead.innerHTML = html;
		}

		function fetchUsers() {
			if(!isAdmin) return;
			fetch('/api/users', {headers:{'Authorization':'Bearer '+token}})
			.then(function(r){ if(!r.ok) throw new Error('HTTP '+r.status); return r.json(); })
			.then(function(data){
				var tbody=document.getElementById('usersBody');
				tbody.innerHTML='';
				data.forEach(function(u){
					var lockedStatus=u.locked?'🔒':'🔓';
					var lockBtn = u.locked 
				? '<button class="btn btn-unlock btn-sm" onclick="toggleLock(\'' + u.id + '\', false)">Unlock</button>' 
				: '<button class="btn btn-lock btn-sm" onclick="toggleLock(\'' + u.id + '\', true)">Lock</button>';
					var row=document.createElement('tr');
					row.innerHTML='<td>'+u.id+'</td><td><input class="editable" value="'+esc(u.username)+'" data-field="username" data-id="'+u.id+'" onchange="updateUserField(this)"></td><td><select data-field="role" data-id="'+u.id+'" onchange="updateUserField(this)"><option value="user" '+(u.role==='user'?'selected':'')+'>User</option><option value="admin" '+(u.role==='admin'?'selected':'')+'>Admin</option></select></td><td>'+lockedStatus+'</td><td>'+new Date(u.created_at).toLocaleString()+'</td><td>'+lockBtn+' <button class="btn btn-delete btn-sm" onclick="deleteUser(\'' + u.id + '\')">🗑</button></td>';
					tbody.appendChild(row);
				});
				var sel=document.getElementById('userIdSelect');
				sel.innerHTML='<option value="">Select User</option>';
				data.forEach(function(u){ sel.innerHTML+='<option value="'+u.id+'">'+u.username+' ('+u.role+')</option>'; });
			})
			.catch(function(err){ showToast('Fetch users error: '+err.message,'error'); });
		}

		function fetchAccounts() {
			var url = isAdmin ? '/api/accounts' : '/api/user/accounts';
			fetch(url, {headers:{'Authorization':'Bearer '+token}})
			.then(function(r){ if(!r.ok) throw new Error('HTTP '+r.status); return r.json(); })
			.then(function(data){
				if(isAdmin) {
					fetch('/api/users', {headers:{'Authorization':'Bearer '+token}})
					.then(function(r){ return r.json(); })
					.then(function(users){
						var userMap={}; users.forEach(function(u){ userMap[u.id]=u.username; });
						renderAccounts(data, userMap);
						hideNonAdminActions();
					})
					.catch(function(err){ showToast('Error fetching users: '+err.message,'error'); });
				} else {
					renderAccounts(data, {});
					hideNonAdminActions();
				}
			})
			.catch(function(err){ showToast('Fetch accounts error: '+err.message,'error'); });
		}

		function renderAccounts(accounts, userMap) {
			var tbody = document.getElementById('accountsBody');
			tbody.innerHTML = '';
			if (!accounts || accounts.length === 0) {
				tbody.innerHTML = '<tr><td colspan="16" style="text-align:center;color:#888;padding:20px;">No accounts found.</td></tr>';
				return;
			}
			var isLocked = !isAdmin && locked;
			var editable = !isLocked || isAdmin;
			var disabledAttr = isAdmin ? '' : 'disabled';
			accounts.forEach(function(acc) {
				var statusClass = 'status-'+acc.status;
				var html = '';
				var isChecked = selectedAccounts[acc.id] === true;
				var checkedAttr = isChecked ? 'checked' : '';
				html += '<td><div class="checkbox-wrapper">';
				html += '<input type="checkbox" class="account-checkbox" data-account-id="'+acc.id+'" '+checkedAttr+'>';
				html += '</div></td>';
				html += '<td style="color:#888;font-size:12px;text-align:center;">' + (acc.sl || '-') + '</td>';
				if (isAdmin) {
					// Admin: ID + User একসাথে
					html += '<td><div style="display:flex;flex-direction:column;gap:2px;">';
					html += '<div><span style="font-family:monospace;font-size:11px;">' + trunc(acc.id, 5) + '</span>';
					html += '<div style="font-size:11px;color:#888;">' + (userMap[acc.user_id] || '-') + '</div>';
					html += '</div></td>';
				} else if (!locked) {
					// Non-admin: শুধু ID
					html += '<td><span style="font-family:monospace;font-size:11px;">' + trunc(acc.id, 10) + '</span></td>';
				}
				html += '<td><div style="display:flex;flex-direction:column;gap:3px;">' + (editable ? '<div><input class="editable" value="'+esc(acc.phone)+'" data-field="phone" data-id="'+acc.id+'" onchange="updateAccountField(this)" style="font-size:12px;"></div>' : '<div style="font-size:12px;">'+esc(acc.phone)+'</div>') + (editable ? '<div><input class="editable" value="'+esc(acc.password)+'" data-field="password" data-id="'+acc.id+'" onchange="updateAccountField(this)" style="font-size:12px;"></div>' : '<div style="font-size:12px;">'+esc(acc.password)+'</div>') + '<div class="status-cell '+statusClass+'" style="font-size:14px;">'+acc.status.replace(/_/g,' ')+'</div>' + '</div></td>';
				html += '<td>'+(editable?'<input class="editable" value="'+esc(acc.otp)+'" data-field="otp" data-id="'+acc.id+'" onchange="updateAccountField(this)">':esc(acc.otp))+'</td>';
				html += '<td><div class="token-cell"><span class="token-trunc">'+trunc(acc.access_token,14)+'</span><button class="btn-copy" data-token="'+esc(acc.access_token)+'">📋</button></div></td>';
				html += '<td>'+trunc(acc.reservation_id,10)+'</td>';
				html += '<td>'+(editable?'<input class="editable" value="'+esc(acc.appointment_id)+'" data-field="appointment_id" data-id="'+acc.id+'" onchange="updateAccountField(this)">':esc(acc.appointment_id))+'</td>';

				var missionHtml = '<select class="editable" data-field="mission" data-id="'+acc.id+'" onchange="updateAccountField(this)" style="font-size:12px;">';
				for (var key in MISSION_DATA) {
					var selected = (acc.mission === MISSION_DATA[key].mission) ? 'selected' : '';
					missionHtml += '<option value="'+key+'" '+selected+'>'+MISSION_DATA[key].mission+'</option>';
				}
				missionHtml += '</select>';

				html += '<td>';
				if (editable) {
					html += '<div style="display:flex;flex-direction:column;gap:3px;">';
					html += '<div>' + missionHtml + '</div>';
					html += '<div><input class="editable" value="'+esc(acc.ivac_center)+'" data-field="ivac_center" data-id="'+acc.id+'" onchange="updateAccountField(this)" style="font-size:11px;color:#aaa;"></div>';
					html += '</div>';
				} else {
					html += '<div style="display:flex;flex-direction:column;gap:2px;">';
					html += '<div>' + esc(acc.mission) + '</div>';
					html += '<div style="font-size:11px;color:#888;">' + esc(acc.ivac_center) + '</div>';
					html += '</div>';
				}
				html += '</td>';
				html += '<td style="width:120px;min-width:100px;text-align:center;vertical-align:middle;">';
				if (acc.payment_link) {
					html += '<a href="'+acc.payment_link+'" target="_blank" class="btn btn-pay pay-btn" '
						+  'data-account-id="'+acc.id+'" '
						+  'onclick="markPayClicked(this)">PAY</a>';
				}
				html += '</td>';

				var otpFetched = acc.otp_fetched_at ? new Date(acc.otp_fetched_at) : null;
				var otpFetchedStr = otpFetched ? otpFetched.toLocaleString() : '-';
				html += '<td>';
				html += '<div style="font-size:11px;color:#e0e0e0;">' + otpFetchedStr + '</div>';

				if (otpFetched) {
					var expiresAt = otpFetched.getTime() + 15 * 60 * 1000;
					var now = Date.now();
					var remaining = expiresAt - now;

					if (remaining <= 0) {
						html += '<div style="font-size:10px;color:#ff6b6b;margin-top:2px;font-weight:700;" id="expires-' + acc.id + '">✗ Session Expired</div>';
					} else {
						var mins = Math.floor(remaining / 60000);
						var secs = Math.floor((remaining % 60000) / 1000);
						var cdText = mins + ':' + (secs < 10 ? '0' : '') + secs;
						html += '<div style="font-size:10px;color:#00d4ff;margin-top:2px;" id="expires-' + acc.id + '">→ ' + cdText + '</div>';
					}
				}
				html += '</td>';
				var otpCountdown = '-';
				if(otpFetched) {
					var elapsed = (Date.now()-otpFetched.getTime())/1000;
					var remaining = 300 - elapsed; if(remaining<0) remaining=0;
					var mins=Math.floor(remaining/60), secs=Math.floor(remaining%60);
					otpCountdown = mins+':'+(secs<10?'0':'')+secs;
					if(remaining<=0) otpCountdown='Expired';
				}
				html += '<td class="countdown" id="otp-cd-'+acc.id+'">'+otpCountdown+'</td>';

				var payAt = acc.payment_link_at ? new Date(acc.payment_link_at) : null;
				var payAtStr = payAt ? payAt.toLocaleString() : '-';
				html += '<td>'+payAtStr+'</td>';
				var payCountdown = '-';
				if(payAt) {
					var elapsed = (Date.now()-payAt.getTime())/1000;
					var remaining = 300 - elapsed; if(remaining<0) remaining=0;
					var mins=Math.floor(remaining/60), secs=Math.floor(remaining%60);
					payCountdown = mins+':'+(secs<10?'0':'')+secs;
					if(remaining<=0) payCountdown='Expired';
				}
				html += '<td class="countdown" id="pay-cd-'+acc.id+'">'+payCountdown+'</td>';

				var fileCount = (acc.upload_files && acc.upload_files.length) ? acc.upload_files.length : 0;
				var fileLabel = fileCount > 0 ? '📄 ' + fileCount + ' file(s)' : 'No files';
				html += '<td><div class="file-list" style="display:flex;align-items:center;gap:6px;">';
				html += '<span style="color:' + (fileCount > 0 ? '#00d4ff' : '#888') + ';font-size:13px;font-weight:500;">' + fileLabel + '</span>';
				html += '<button class="btn btn-upload btn-sm btn-manage-files" data-account-id="'+acc.id+'" style="padding:2px 8px;font-size:11px;">📤 Manage</button>';
				html += '</div></td>';

				html += '<td>' +
					'<select class="step-select" data-id="'+esc(acc.id)+'" ' + disabledAttr + '>' +
						'<option value="0" selected>Start</option>' +
						'<option value="1">Sign Token</option>' +
						'<option value="2">Signin</option>' +
						'<option value="3">Otp Read</option>' +
						'<option value="4">Otp Verify</option>' +
						'<option value="5">Confirmation</option>' +
						'<option value="6">Appointment</option>' +
						'<option value="7">Upload</option>' +
						'<option value="8">Mission</option>' +
						'<option value="9">Booking Config</option>' +
						'<option value="10">Reserve Token</option>' +
						'<option value="11">Reserve</option>' +
						'<option value="12">Pay Token</option>' +
						'<option value="13">Initiate</option>' +
					'</select> ' +
					'<button class="btn btn-start btn-sm btn-action-start" data-account-id="'+acc.id+'" ' + disabledAttr + '>▶</button> ' +
					'<button class="btn btn-stop btn-sm btn-action-stop" data-account-id="'+acc.id+'" ' + disabledAttr + '>⏹</button> ' +
					'<button class="btn btn-delete btn-sm btn-delete-account" data-account-id="'+acc.id+'" ' + disabledAttr + '>🗑</button>' +
				'</td>';

				if(isAdmin) {
					html += '<td><input class="editable" value="'+esc(acc.ip)+'" data-field="ip" data-id="'+acc.id+'" onchange="updateAccountField(this)"></td>';
					html += '<td><button class="btn btn-reset btn-sm btn-reset-account" data-account-id="'+acc.id+'">🔄 Reset</button></td>';
				}

				var row = document.createElement('tr');
				row.dataset.accountId = acc.id;
				if (selectedAccounts[acc.id]) {
					row.className = 'selected';
				}
				row.innerHTML = html;
				tbody.appendChild(row);
				if(otpFetched) row.dataset.otpFetched = otpFetched.getTime();
				if(payAt) row.dataset.payAt = payAt.getTime();
			});
			updateCountdowns();
		}

		document.addEventListener('click', function(e) {
			var target = e.target;
			if (target.classList.contains('btn-manage-files')) {
				var accountId = target.getAttribute('data-account-id');
				if (accountId) openFileModal(accountId);
				return;
			}
			if (target.classList.contains('btn-delete-file')) {
				var accountId = target.getAttribute('data-account-id');
				var filename = target.getAttribute('data-filename');
				if (accountId && filename) deleteFile(accountId, filename);
				return;
			}
			if (target.classList.contains('btn-copy')) {
				var token = target.getAttribute('data-token');
				if (token) copyToken(token, target);
				return;
			}
			if (target.classList.contains('btn-action-start')) {
				var accountId = target.getAttribute('data-account-id');
				var row = target.closest('tr');
				var select = row ? row.querySelector('.step-select') : null;
				var step = select ? parseInt(select.value) : 0;
				if (accountId) actionWithStep('start', step, accountId);
				return;
			}
			if (target.classList.contains('btn-action-stop')) {
				var accountId = target.getAttribute('data-account-id');
				if (accountId) action('stop', accountId);
				return;
			}
			if (target.classList.contains('btn-delete-account')) {
				var accountId = target.getAttribute('data-account-id');
				if (accountId) deleteAccount(accountId);
				return;
			}
			if (target.classList.contains('btn-reset-account')) {
				var accountId = target.getAttribute('data-account-id');
				if (accountId) resetAccount(accountId);
				return;
			}
		});

		// রো ক্লিক করে চেকবক্স টগল করুন (বাটন/ইনপুট বাদে)
document.addEventListener('click', function(e) {
    var target = e.target;
    var row = target.closest('tr');
    if (!row || !row.dataset.accountId) return;
    
    // চেক করুন ক্লিক করা এলিমেন্ট কি ইন্টারঅ্যাক্টিভ এলিমেন্টের ভিতরে?
    var interactiveElements = ['input', 'select', 'button', 'a'];
    var tagName = target.tagName.toLowerCase();
    var isInteractive = interactiveElements.includes(tagName);
    
    // চেক করুন ক্লিক করা এলিমেন্ট কি ইন্টারঅ্যাক্টিভ এলিমেন্টের প্যারেন্ট?
    var isInsideInteractive = !!target.closest('input, select, button, a');
    
    // যদি ইন্টারঅ্যাক্টিভ এলিমেন্টে ক্লিক না করা হয়, তাহলে চেকবক্স টগল করুন
    if (!isInteractive && !isInsideInteractive) {
        var checkbox = row.querySelector('.account-checkbox');
        if (checkbox) {
            checkbox.checked = !checkbox.checked;
            // ইভেন্ট ট্রিগার করুন যাতে selectedAccounts আপডেট হয়
            var event = new Event('change', { bubbles: true });
            checkbox.dispatchEvent(event);
            
            // ভিজ্যুয়াল ফিডব্যাক - selected ক্লাস যোগ/রিমুভ
            if (checkbox.checked) {
                row.classList.add('selected');
            } else {
                row.classList.remove('selected');
            }
        }
    }
});

// চেকবক্স পরিবর্তনে selected ক্লাস আপডেট করুন
document.addEventListener('change', function(e) {
    if (e.target && e.target.classList.contains('account-checkbox')) {
        var row = e.target.closest('tr');
        if (row) {
            if (e.target.checked) {
                row.classList.add('selected');
            } else {
                row.classList.remove('selected');
            }
        }
        var accountId = e.target.getAttribute('data-account-id');
        if (e.target.checked) {
            selectedAccounts[accountId] = true;
        } else {
            delete selectedAccounts[accountId];
        }
        updateSelectAllState(); // ← ইতিমধ্যে আছে
    }
});
		function updateCountdowns() {
			document.querySelectorAll('#accountsBody tr').forEach(function(row) {
				var accId = row.dataset.accountId;
				var otpTime = row.dataset.otpFetched;
				if(otpTime) {
					var el = document.getElementById('otp-cd-'+accId);
					if(el) {
						var elapsed = (Date.now()-parseInt(otpTime))/1000;
						var remaining = 300 - elapsed; if(remaining<0) remaining=0;
						var mins=Math.floor(remaining/60), secs=Math.floor(remaining%60);
						el.textContent = remaining>0 ? mins+':'+(secs<10?'0':'')+secs : 'Expired';
					}
				}
				var otpTime2 = row.dataset.otpFetched;
				if (otpTime2) {
					var el = document.getElementById('expires-' + accId);
					if (el) {
						var expiresAt = parseInt(otpTime2) + 15 * 60 * 1000;
						var remaining = expiresAt - Date.now();

						if (remaining <= 0) {
							if (el.textContent.indexOf('Expired') === -1) {
								el.textContent = '✗ Session Expired';
								el.style.color = '#ff6b6b';
								el.style.fontWeight = '700';
							}
						} else {
							var mins = Math.floor(remaining / 60000);
							var secs = Math.floor((remaining % 60000) / 1000);
							el.textContent = '→ ' + mins + ':' + (secs < 10 ? '0' : '') + secs;

							// ২ মিনিট বা কম বাকি হলে লাল, নাহলে নীল
							if (remaining <= 120000) {
								el.style.color = '#ff6b6b';
								el.style.fontWeight = '700';
							} else {
								el.style.color = '#00d4ff';
								el.style.fontWeight = 'normal';
							}
						}
					}
				}
				var payTime = row.dataset.payAt;
				if(payTime) {
					var el = document.getElementById('pay-cd-'+accId);
					if(el) {
						var elapsed = (Date.now()-parseInt(payTime))/1000;
						var remaining = 300 - elapsed; if(remaining<0) remaining=0;
						var mins=Math.floor(remaining/60), secs=Math.floor(remaining%60);
						el.textContent = remaining>0 ? mins+':'+(secs<10?'0':'')+secs : 'Expired';
					}
				}
			});
		}
		setInterval(updateCountdowns, 1000);

		function updateAccountField(input) {
			if(locked && !isAdmin){ showToast('Locked','error'); return; }
			var url = isAdmin ? '/api/update' : '/api/user/accounts/'+input.dataset.id;
			var method = isAdmin ? 'POST' : 'PUT';
			var body = isAdmin ? JSON.stringify({id:input.dataset.id, field:input.dataset.field, value:input.value}) : JSON.stringify({field:input.dataset.field, value:input.value});
			fetch(url, {method:method, headers:{'Content-Type':'application/json','Authorization':'Bearer '+token}, body:body})
			.then(function(r){ if(!r.ok) throw new Error('HTTP '+r.status); return r.json(); })
			.then(function(){ showToast('Updated','success'); fetchAccounts(); })
			.catch(function(err){ showToast('Update failed: '+err.message,'error'); });
		}

		function updateUserField(input) {
			var value = input.tagName==='SELECT' ? input.value : input.value;
			fetch('/api/users/'+input.dataset.id, {method:'PUT', headers:{'Content-Type':'application/json','Authorization':'Bearer '+token}, body:JSON.stringify({field:input.dataset.field, value:value})})
			.then(function(){ showToast('User updated','success'); fetchUsers(); })
			.catch(function(err){ showToast('Update failed: '+err.message,'error'); });
		}

		function toggleLock(userId, lock) {
			fetch('/api/users/'+userId, {method:'PUT', headers:{'Content-Type':'application/json','Authorization':'Bearer '+token}, body:JSON.stringify({field:'locked', value:lock?"true":"false"})})
			.then(function(){ showToast('User '+(lock?'locked':'unlocked'),'success'); fetchUsers(); if(userId===localStorage.getItem('user_id')){ localStorage.setItem('locked',lock); location.reload(); } })
			.catch(function(err){ showToast('Toggle lock failed: '+err.message,'error'); });
		}

		function saveAccount() {
			var phone = document.getElementById('phone').value.trim();
			var password = document.getElementById('password').value.trim();
			if(!phone || !password){ showToast('Phone and Password required','error'); return; }
			var missionData = MISSION_DATA["DHAKA"];
			var url, body;
			if(isAdmin) {
				var userId = document.getElementById('userIdSelect').value;
				if(!userId){ showToast('Select user','error'); return; }
				url = '/api/save';
				body = JSON.stringify({
					phone: phone,
					password: password,
					ip: "",
					otp: "",
					user_id: userId,
					mission: missionData.mission,
					ivac_center: missionData.ivacCenter
				});
			} else {
				if(locked){ showToast('Locked','error'); return; }
				url = '/api/user/accounts';
				body = JSON.stringify({
					phone: phone,
					password: password,
					appointment_id: '',
					mission: missionData.mission,
					ivac_center: missionData.ivacCenter
				});
			}
			fetch(url, {method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer '+token}, body:body})
			.then(function(r){ if(!r.ok) throw new Error('HTTP '+r.status); return r.json(); })
			.then(function(data){ if(data.success){ document.getElementById('phone').value=''; document.getElementById('password').value=''; showToast('Account added','success'); fetchAccounts(); } else { showToast('Save failed: '+(data.message||'unknown'),'error'); } })
			.catch(function(err){ showToast('Save error: '+err.message,'error'); });
		}

		function addUser() {
			var username = document.getElementById('userUsername').value.trim();
			var password = document.getElementById('userPassword').value.trim();
			var role = document.getElementById('userRole').value;
			if(!username || !password){ showToast('Username and Password required','error'); return; }
			fetch('/api/users', {method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer '+token}, body:JSON.stringify({username:username, password:password, role:role})})
			.then(function(){ document.getElementById('userUsername').value=''; document.getElementById('userPassword').value=''; showToast('User added','success'); fetchUsers(); })
			.catch(function(err){ showToast('Add user failed: '+err.message,'error'); });
		}

		function deleteUser(id){fetch('/api/users/'+id, {method:'DELETE', headers:{'Authorization':'Bearer '+token}}).then(function(){ showToast('User deleted','success'); fetchUsers(); }).catch(function(err){ showToast('Delete failed: '+err.message,'error'); }); }

		function deleteAccount(id){ if(!isAdmin && locked){ showToast('Locked','error'); return; } var url = isAdmin ? '/api/delete' : '/api/user/accounts/'+id; var method = isAdmin ? 'POST' : 'DELETE'; var body = isAdmin ? JSON.stringify({id:id}) : undefined; fetch(url, {method:method, headers:{'Content-Type':'application/json','Authorization':'Bearer '+token}, body:body}).then(function(r){ return r.json(); }).then(function(){ showToast('Account deleted','success'); fetchAccounts(); }).catch(function(err){ showToast('Delete failed: '+err.message,'error'); }); }

		function deleteAllAccounts(){ if(!isAdmin){ showToast('Admin only','error'); return; } if(!confirm('DELETE ALL accounts?')) return; fetch('/api/deleteall', {method:'POST', headers:{'Authorization':'Bearer '+token}}).then(function(){ showToast('All deleted','success'); fetchAccounts(); }).catch(function(err){ showToast('Delete all failed: '+err.message,'error'); }); }

		function action(type, id){ if(!isAdmin){ showToast('Admin only','error'); return; } if(locked && !isAdmin){ showToast('Locked','error'); return; } var url='/api/'+type; fetch(url, {method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer '+token}, body:JSON.stringify({id:id, step:0})}).then(function(){ showToast('Action '+type+' triggered','success'); fetchAccounts(); }).catch(function(err){ showToast('Action failed: '+err.message,'error'); }); }

		function actionWithStep(type, step, id){ if(!isAdmin){ showToast('Admin only','error'); return; } if(locked && !isAdmin){ showToast('Locked','error'); return; } var url='/api/'+type; fetch(url, {method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer '+token}, body:JSON.stringify({id:id, step:step})}).then(function(){ showToast('Action '+type+' step '+step+' triggered','success'); fetchAccounts(); }).catch(function(err){ showToast('Action failed: '+err.message,'error'); }); }

		function autoAll(){ if(!isAdmin){ showToast('Admin only','error'); return; } if(locked && !isAdmin){ showToast('Locked','error'); return; } var step=parseInt(document.getElementById('globalStepSelect').value)||0; fetch('/api/autoall', {method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer '+token}, body:JSON.stringify({step:step})}).then(function(){ showToast('Auto All started from step '+step,'success'); fetchAccounts(); }).catch(function(err){ showToast('Auto All failed: '+err.message,'error'); }); }

		function stopAll(){ if(!isAdmin){ showToast('Admin only','error'); return; } if(locked && !isAdmin){ showToast('Locked','error'); return; } fetch('/api/stopall', {method:'POST', headers:{'Authorization':'Bearer '+token}}).then(function(){ showToast('All stopped','success'); fetchAccounts(); }).catch(function(err){ showToast('Stop all failed: '+err.message,'error'); }); }

		function updateConfigField(fieldName){ if(!isAdmin) return; var el=document.getElementById(fieldName); if(!el) return; var value = el.type==='checkbox' ? el.checked : parseInt(el.value); var payload={}; payload[fieldName]=value; fetch('/api/config', {method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer '+token}, body:JSON.stringify(payload)}).then(function(r){ return r.json(); }).then(function(data){ if(data.success) showToast('Config updated: '+fieldName+'='+value,'success'); else showToast('Config update failed','error'); }).catch(function(err){ showToast('Config error: '+err.message,'error'); }); }

		function toggleAllAccounts(checked) {
    // শুধু visible (display !== 'none') চেকবক্সগুলো সিলেক্ট করবে
    document.querySelectorAll('.account-checkbox').forEach(function(cb) {
        var row = cb.closest('tr');
        // চেক করুন row টি visible কিনা
        if (row && row.style.display !== 'none') {
            cb.checked = checked;
            var accountId = cb.getAttribute('data-account-id');
            if (checked) {
                selectedAccounts[accountId] = true;
                row.classList.add('selected');
            } else {
                delete selectedAccounts[accountId];
                row.classList.remove('selected');
            }
        }
    });
}

		// Get selected account IDs
		function getSelectedAccountIds() {
			var ids = [];
			document.querySelectorAll('.account-checkbox:checked').forEach(function(cb) {
				ids.push(cb.getAttribute('data-account-id'));
			});
			return ids;
		}

		// Auto Selected - একাধিক অ্যাকাউন্ট একসাথে চালু
		function autoSelected() {
			if (!isAdmin) { showToast('Admin only','error'); return; }
			if (locked && !isAdmin) { showToast('Locked','error'); return; }
			
			var ids = getSelectedAccountIds();
			if (ids.length === 0) {
				showToast('Please select at least one account','error');
				return;
			}
			
			var step = parseInt(document.getElementById('globalStepSelect').value) || 0;
			
			fetch('/api/autoselected', {
				method: 'POST',
				headers: {'Content-Type':'application/json','Authorization':'Bearer '+token},
				body: JSON.stringify({ids: ids, step: step})
			})
			.then(function(r){ return r.json(); })
			.then(function(data){
				showToast('Auto started for '+ids.length+' accounts from step '+step,'success');
				fetchAccounts();
			})
			.catch(function(err){ showToast('Auto Selected failed: '+err.message,'error'); });
		}

		// Stop Selected - নির্বাচিত অ্যাকাউন্টগুলো বন্ধ করুন
		function stopSelected() {
			if (!isAdmin) { showToast('Admin only','error'); return; }
			if (locked && !isAdmin) { showToast('Locked','error'); return; }
			
			var ids = getSelectedAccountIds();
			if (ids.length === 0) {
				showToast('Please select at least one account','error');
				return;
			}
			
			fetch('/api/stopselected', {
				method: 'POST',
				headers: {'Content-Type':'application/json','Authorization':'Bearer '+token},
				body: JSON.stringify({ids: ids})
			})
			.then(function(){ showToast('Stopped '+ids.length+' accounts','success'); fetchAccounts(); })
			.catch(function(err){ showToast('Stop Selected failed: '+err.message,'error'); });
		}
			
		function resetAccount(id){ fetch('/api/reset', {method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer '+token}, body:JSON.stringify({id:id})}).then(function(r){ return r.json(); }).then(function(data){ if(data.success){ showToast('Reset successful','success'); fetchAccounts(); } else { showToast('Reset failed: '+(data.message||'unknown'),'error'); } }).catch(function(err){ showToast('Reset error: '+err.message,'error'); }); }

		var currentModalAccount = '';
		var currentModalMissionKey = 'DHAKA';

		function openFileModal(accountId) {
			currentModalAccount = accountId;
			document.getElementById('modalAccountId').textContent = accountId;
			fetch('/api/accounts', {headers:{'Authorization':'Bearer '+token}})
			.then(function(r){ return r.json(); })
			.then(function(accounts){
				var acc = accounts.find(function(a){ return a.id == accountId; });
				if(acc && acc.mission) {
					for (var key in MISSION_DATA) {
						if (MISSION_DATA[key].mission === acc.mission) {
							currentModalMissionKey = key;
							break;
						}
					}
				}
				document.getElementById('modalMissionSelect').value = currentModalMissionKey;
				loadFiles(accountId);
			})
			.catch(function(){ loadFiles(accountId); });
			document.getElementById('fileModal').style.display = 'block';
		}

		function closeFileModal() { document.getElementById('fileModal').style.display = 'none'; }

		function updateMissionFromModal() {
			var key = document.getElementById('modalMissionSelect').value;
			var data = MISSION_DATA[key];
			if (!data) return;
			var accId = currentModalAccount;
			fetch('/api/update', {
				method:'POST',
				headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
				body:JSON.stringify({id:accId, field:'mission', value:data.mission})
			})
			.then(function(r){ return r.json(); })
			.then(function(){
				fetch('/api/update', {
					method:'POST',
					headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
					body:JSON.stringify({id:accId, field:'ivac_center', value:data.ivacCenter})
				})
				.then(function(){ showToast('Mission updated to '+data.mission,'success'); fetchAccounts(); })
				.catch(function(err){ showToast('Failed to update mission: '+err.message,'error'); });
			})
			.catch(function(err){ showToast('Failed to update mission: '+err.message,'error'); });
		}

		function loadFiles(accountId) {
			fetch('/api/accounts/'+accountId+'/files', {headers:{'Authorization':'Bearer '+token}})
			.then(function(r){ return r.json(); })
			.then(function(data) {
				var container = document.getElementById('fileListContainer');
				container.innerHTML = '';
				if(data.files && data.files.length) {
					data.files.forEach(function(f) {
						var div = document.createElement('div');
						div.className = 'file-item';
						div.innerHTML = '<span class="fname">'+esc(f)+'</span><button class="btn btn-danger btn-sm btn-delete-file" data-account-id="'+accountId+'" data-filename="'+esc(f)+'">✕</button>';
						container.appendChild(div);
					});
				} else {
					container.innerHTML = '<span style="color:#888;">No files uploaded.</span>';
				}
			})
			.catch(function(err){ showToast('Load files error: '+err.message,'error'); });
		}
// ============================================================
// রিয়েল-টাইম ফিল্টার ফাংশন
// ============================================================

var currentFilter = '';
var filterTimeout = null;

function applyFilter() {
    var input = document.getElementById('statusFilter');
    if (!input) return;
    var filterText = input.value.trim().toLowerCase();
    currentFilter = filterText;
    filterAccounts(filterText);
    updateSelectAllState(); // ← যোগ করুন
}

function clearFilter() {
    var input = document.getElementById('statusFilter');
    if (input) input.value = '';
    currentFilter = '';
    filterAccounts('');
    updateSelectAllState(); // ← যোগ করুন
}

function filterAccounts(filterText) {
    var rows = document.querySelectorAll('#accountsBody tr');
    var visibleCount = 0;
    var totalCount = 0;
    
    rows.forEach(function(row) {
        if (!row.dataset.accountId) return;
        totalCount++;
        
        var statusCell = row.querySelector('.status-cell');
        if (!statusCell) {
            row.style.display = '';
            visibleCount++;
            return;
        }
        
        var statusText = statusCell.textContent.trim().toLowerCase();
        
        if (filterText === '') {
            row.style.display = '';
            visibleCount++;
        } else if (statusText.includes(filterText)) {
            row.style.display = '';
            visibleCount++;
        } else {
            row.style.display = 'none';
            // ★★★ ফিল্টারের বাইরের row থেকে selected ক্লাস সরান ★★★
            row.classList.remove('selected');
            // ★★★ ফিল্টারের বাইরের checkbox unchecked করুন ★★★
            var cb = row.querySelector('.account-checkbox');
            if (cb) {
                cb.checked = false;
                delete selectedAccounts[row.dataset.accountId];
            }
        }
    });
    
    // selectAll চেকবক্স আপডেট করুন
    updateSelectAllState();
    
    var countSpan = document.getElementById('filterCount');
    if (countSpan) {
        if (filterText === '') {
            countSpan.textContent = 'Showing all ' + totalCount + ' accounts';
        } else {
            countSpan.textContent = 'Showing ' + visibleCount + ' of ' + totalCount + ' accounts (filter: "' + filterText + '")';
        }
    }
}
function updateSelectAllState() {
    var checkboxes = document.querySelectorAll('.account-checkbox');
    var visibleCheckboxes = [];
    var checkedVisible = 0;
    
    checkboxes.forEach(function(cb) {
        var row = cb.closest('tr');
        // শুধু visible row গুলো কাউন্ট করুন
        if (row && row.style.display !== 'none') {
            visibleCheckboxes.push(cb);
            if (cb.checked) {
                checkedVisible++;
            }
        }
    });
    
    var selectAll = document.getElementById('selectAll');
    if (selectAll) {
        if (visibleCheckboxes.length === 0) {
            selectAll.checked = false;
            selectAll.indeterminate = false;
        } else if (checkedVisible === visibleCheckboxes.length) {
            selectAll.checked = true;
            selectAll.indeterminate = false;
        } else if (checkedVisible > 0 && checkedVisible < visibleCheckboxes.length) {
            selectAll.checked = false;
            selectAll.indeterminate = true; // মixed স্টেট
        } else {
            selectAll.checked = false;
            selectAll.indeterminate = false;
        }
    }
}
document.addEventListener('DOMContentLoaded', function() {
    var filterInput = document.getElementById('statusFilter');
    if (filterInput) {
        filterInput.addEventListener('input', function() {
            clearTimeout(filterTimeout);
            filterTimeout = setTimeout(function() {
                applyFilter();
                // ★★★ ফিল্টার করার পর selectAll স্টেট আপডেট করুন ★★★
                updateSelectAllState();
            }, 150);
        });
        
        filterInput.addEventListener('keyup', function(e) {
            if (e.key === 'Enter') {
                clearTimeout(filterTimeout);
                applyFilter();
                updateSelectAllState();
            }
        });
    }
});

// fetchAccounts ওভাররাইড - ফিল্টার সংরক্ষণ
var originalFetchAccounts = fetchAccounts;
fetchAccounts = function() {
    originalFetchAccounts();
    setTimeout(function() {
        if (currentFilter) {
            filterAccounts(currentFilter);
            updateSelectAllState(); // ← যোগ করুন
        }
    }, 150);
};

		// ============================================================
// File Upload — Click + Drag & Drop + Progress
// ============================================================

function initFileUpload() {
    var dropZone = document.getElementById('dropZone');
    var fileInput = document.getElementById('fileInput');

    if (!dropZone || !fileInput) {
        console.warn('[UPLOAD] dropZone or fileInput not found');
        return;
    }

    // ★ Click → file dialog
    dropZone.addEventListener('click', function(e) {
        if (e.target.tagName !== 'INPUT') {
            fileInput.click();
        }
    });

    // ★ File select → auto upload
    fileInput.addEventListener('change', function() {
        if (fileInput.files.length > 0) {
            uploadFiles();
        }
    });

    // ★ Drag over — highlight
    dropZone.addEventListener('dragover', function(e) {
        e.preventDefault();
        e.stopPropagation();
        dropZone.style.borderColor = '#00d4ff';
        dropZone.style.background = '#1a2a3e';
    });

    // ★ Drag leave — unhighlight
    dropZone.addEventListener('dragleave', function(e) {
        e.preventDefault();
        e.stopPropagation();
        dropZone.style.borderColor = '#444';
        dropZone.style.background = 'transparent';
    });

    // ★ Drop — files নিন এবং upload
    dropZone.addEventListener('drop', function(e) {
        e.preventDefault();
        e.stopPropagation();
        dropZone.style.borderColor = '#444';
        dropZone.style.background = 'transparent';

        var files = e.dataTransfer.files;
        if (!files || files.length === 0) return;

        try {
            fileInput.files = files;
        } catch (err) {
            console.warn('FileList assign failed:', err);
        }

        uploadFiles(files);
    });
}

// DOM ready চেক
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initFileUpload);
} else {
    initFileUpload();
}

// ============================================================
// Upload Progress Control
// ============================================================

function showUploadProgress(text, percent) {
    var content = document.getElementById('dropZoneContent');
    var loading = document.getElementById('dropZoneLoading');
    var textEl = document.getElementById('dropZoneProgressText');
    var barEl = document.getElementById('dropZoneProgressBar');

    if (content) content.style.visibility = 'hidden';
    if (loading) loading.style.display = 'flex';
    if (textEl) textEl.textContent = text || 'Uploading...';
    if (barEl) barEl.style.width = (percent || 0) + '%';
}

function hideUploadProgress() {
    var content = document.getElementById('dropZoneContent');
    var loading = document.getElementById('dropZoneLoading');
    var barEl = document.getElementById('dropZoneProgressBar');

    if (content) content.style.visibility = 'visible';
    if (loading) loading.style.display = 'none';
    if (barEl) barEl.style.width = '0%';
}

function updateUploadProgress(percent) {
    var barEl = document.getElementById('dropZoneProgressBar');
    var textEl = document.getElementById('dropZoneProgressText');
    if (barEl) barEl.style.width = percent + '%';
    if (textEl) textEl.textContent = 'Uploading... ' + Math.round(percent) + '%';
}

// ============================================================
// uploadFiles — XHR based with progress tracking
// ============================================================

function uploadFiles(filesFromDrop) {
    var input = document.getElementById('fileInput');
    var files = filesFromDrop || input.files;

    if (!files || files.length === 0) {
        showToast('Select a file', 'error');
        return;
    }

    // ★ Validate files
    for (var i = 0; i < files.length; i++) {
        if (files[i].size > 10 * 1024 * 1024) {
            showToast('File too large (max 10MB)', 'error');
            return;
        }
        if (!files[i].name.toLowerCase().endsWith('.pdf')) {
            showToast('Only PDF allowed', 'error');
            return;
        }
    }

    // ★ Build FormData
    var formData = new FormData();
    for (var i = 0; i < files.length; i++) {
        formData.append('file', files[i]);
    }

    // ★ Show progress overlay
    showUploadProgress('Preparing upload...', 0);

    // ★ XHR — progress event এর জন্য
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/accounts/' + currentModalAccount + '/files', true);
    xhr.setRequestHeader('Authorization', 'Bearer ' + token);
    xhr.timeout = 5 * 60 * 1000; // 5 minutes

    // ★ Upload progress
    xhr.upload.onprogress = function(e) {
        if (e.lengthComputable) {
            var percent = (e.loaded / e.total) * 100;
            updateUploadProgress(percent);
        }
    };

    // ★ Upload start
    xhr.upload.onloadstart = function() {
        showUploadProgress('Uploading...', 0);
    };

    // ★ Upload finished (server processing চলছে)
    xhr.upload.onload = function() {
        showUploadProgress('Processing on server...', 100);
    };

    // ★ Response received
    xhr.onload = function() {
        hideUploadProgress();

        if (xhr.status >= 200 && xhr.status < 300) {
            try {
                var data = JSON.parse(xhr.responseText);
                if (data.success) {
                    showToast('✅ File(s) uploaded successfully', 'success');
                    loadFiles(currentModalAccount);
                    if (input) input.value = '';
                } else {
                    showToast('Upload failed: ' + (data.message || 'unknown'), 'error');
                }
            } catch (e) {
                showToast('Invalid server response', 'error');
            }
        } else {
            showToast('Upload failed: HTTP ' + xhr.status, 'error');
        }
    };

    // ★ Error
    xhr.onerror = function() {
        hideUploadProgress();
        showToast('Network error during upload', 'error');
    };

    // ★ Timeout
    xhr.ontimeout = function() {
        hideUploadProgress();
        showToast('Upload timeout — server busy', 'error');
    };

    // ★ Abort
    xhr.onabort = function() {
        hideUploadProgress();
        showToast('Upload cancelled', 'info');
    };

    // ★ Send
    xhr.send(formData);
}

// ============================================================
// Modal close → reset progress
// ============================================================

// পুরোনো closeFileModal কে wrap করুন
var _originalCloseFileModal = closeFileModal;
closeFileModal = function() {
    // Progress overlay reset
    hideUploadProgress();
    _originalCloseFileModal();
};

		function deleteFile(accountId, filename) {
			fetch('/api/accounts/'+accountId+'/files?file='+encodeURIComponent(filename), {
				method:'DELETE',
				headers:{'Authorization':'Bearer '+token}
			})
			.then(function(r){ return r.json(); })
			.then(function(data){
				if(data.success){ showToast('File deleted','success'); loadFiles(accountId); fetchAccounts(); } else { showToast('Delete failed','error'); }
			})
			.catch(function(err){ showToast('Delete error: '+err.message,'error'); });
		}

		function resetSelected() {
	if (!isAdmin) { showToast('Admin only','error'); return; }
	if (locked && !isAdmin) { showToast('Locked','error'); return; }
	
	var ids = getSelectedAccountIds();
	if (ids.length === 0) {
		showToast('Please select at least one account','error');
		return;
	}
	
	if (!confirm('Reset ' + ids.length + ' selected accounts?\n\nThis will:\n- Stop all running tasks\n- Clear all tokens, OTP, appointments\n- Reset status to "idle"\n\nContinue?')) {
		return;
	}
	
	showToast('Resetting ' + ids.length + ' accounts...','info');
	
	fetch('/api/resetselected', {
		method: 'POST',
		headers: {'Content-Type':'application/json','Authorization':'Bearer '+token},
		body: JSON.stringify({ids: ids})
	})
	.then(function(r){ return r.json(); })
	.then(function(data){
		if (data.success) {
			showToast('✅ Reset successful for ' + data.reset_count + ' accounts','success');
			fetchAccounts();
		} else {
			showToast('Reset failed: ' + (data.message || 'unknown'), 'error');
		}
	})
	.catch(function(err){ showToast('Reset Selected failed: '+err.message,'error'); });
}
// ═══════════════════════════════════════════════════════════════
// Extractor Ready Watcher + Toast + Auto-Start
// ═══════════════════════════════════════════════════════════════

var extractorReady = false;
var extractorAutoStarted = false;

function startExtractorWatcher() {
    // প্রতি ২ সেকেন্ডে status poll
    setInterval(checkExtractorStatus, 2000);
    // সাথে সাথে একবার check
    checkExtractorStatus();
}

function checkExtractorStatus() {
    if (extractorReady) return;
    fetch('/api/extractor/status', {
        headers: { 'Authorization': 'Bearer ' + token }
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        // ★ Indicator আপডেট
        if (typeof updateExtractorIndicator === 'function') {
            updateExtractorIndicator(data.ready, data.endpoint_count || 0);
        }
        if (data.ready && !extractorReady) {
            extractorReady = true;
            onExtractorReady(data);
        }
    })
    .catch(function(err) {
        if (typeof updateExtractorIndicator === 'function') {
            updateExtractorIndicator(false, 0);
        }
    });
}

function onExtractorReady(data) {
    var count = data.endpoint_count || 0;

    // ★ Toast notification
    showToast(
        '🎉 Extractor Ready! ' + count + ' endpoints available. Auto-starting automation...',
        'success',
        8000  // 8 সেকেন্ড দেখাবে
    );

    // ★ Auto-start automation
    triggerAutoStart();
}

function triggerAutoStart() {
    if (extractorAutoStarted) return;
    extractorAutoStarted = true;

    var step = parseInt(document.getElementById('globalStepSelect').value) || 0;

    fetch('/api/extractor/autostart', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
        },
        body: JSON.stringify({ step: step })
    })
    .then(function(r) {
        if (!r.ok) {
            return r.json().then(function(e) { throw new Error(e.message || r.status); });
        }
        return r.json();
    })
    .then(function(data) {
        showToast(
            '🚀 Auto-started ' + data.count + ' accounts from step ' + data.step,
            'info',
            6000
        );
        // Accounts table refresh করি
        fetchAccounts();
    })
    .catch(function(err) {
        showToast('Auto-start failed: ' + err.message, 'error', 6000);
        // user manually করতে পারবে
        extractorAutoStarted = false;
    });
}

// ── Dashboard load হওয়া মাত্র watcher চালু
if (isAdmin) {
    startExtractorWatcher();
}
		window.onclick = function(event) { if(event.target == document.getElementById('fileModal')) closeFileModal(); }
				// ═══════════════════════════════════════════════════════════════
		// ═══════════════════════════════════════════════════════════════
// Restart Extractor — PowerShell script invoke করে process reload
// ═══════════════════════════════════════════════════════════════
function updateExtractorIndicator(ready, count) {
    var el = document.getElementById('extractorStatus');
    var txt = document.getElementById('extractorStatusText');
    if (!el || !txt) return;
    el.classList.remove('ok', 'down', 'checking');
    if (ready) {
        el.classList.add('ok');
        txt.textContent = 'Extractor: ' + count + ' endpoints';
    } else {
        el.classList.add('down');
        txt.textContent = 'Extractor: offline';
    }
}

function restartExtractor() {
    // ── Permission check
    if (!isAdmin) { showToast('Admin only', 'error'); return; }

    // ── Double-click guard
    var btn = document.getElementById('btnRestartExtractor');
    if (btn && btn.classList.contains('loading')) return;

    // ── Confirmation
    if (!confirm(
        '🔁 Extractor process restart করবেন?\n\n' +
        '• পুরোনো extractor (port 1111) kill হবে\n' +
        '• নতুন process spawn হবে\n' +
        '• নতুন JS download + deobf + parse\n' +
        '• সময় লাগবে: ৩০ – ৯০ সেকেন্ড\n\n' +
        'চলমান Panel ও automation প্রভাবিত হবে না।\n\n' +
        'চালিয়ে যাবেন?'
    )) return;

    // ═══════════════════════════════════════════════════════════
    // ★★★ CRITICAL — সাথে সাথেই ready flag reset করুন
    // ═══════════════════════════════════════════════════════════
    // না করলে watcher "already ready" ভেবে poll বন্ধ রাখবে
    if (typeof extractorReady !== 'undefined') {
        extractorReady = false;
    }
    if (typeof extractorAutoStarted !== 'undefined') {
        extractorAutoStarted = false;
    }

    // ★★★ Watcher আবার চালু করুন (যদি বন্ধ থাকে)
    if (typeof startExtractorWatcher === 'function') {
        startExtractorWatcher();
    }

    // ★★★ UI indicator আপডেট
    if (typeof updateExtractorIndicator === 'function') {
        updateExtractorIndicator(false, 0);
    }

    // ── Button loading state
    if (btn) {
        btn.classList.add('loading');
        btn.disabled = true;
    }

    // ── Toast notification (2 মিনিট দেখাবে)
    showToast('🔁 Extractor restart চলছে... অপেক্ষা করুন (৬০s পর্যন্ত)', 'info', 120000);

    // ═══════════════════════════════════════════════════════════
    // ★★★ Live countdown timer on button
    // ═══════════════════════════════════════════════════════════
    var startTs = Date.now();
    var countdownInterval = setInterval(function() {
        var elapsed = ((Date.now() - startTs) / 1000).toFixed(0);
        if (btn) {
            btn.textContent = '⏳ ' + elapsed + 's';
        }
    }, 1000);

    // ═══════════════════════════════════════════════════════════
    // ★★★ Backend call
    // ═══════════════════════════════════════════════════════════
    fetch('/api/extractor/restart', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + token }
    })
    .then(function(r) {
        return r.json().then(function(body) {
            return { ok: r.ok, status: r.status, body: body };
        });
    })
    .then(function(res) {
        if (!res.ok) {
            var msg = (res.body && res.body.error) || ('HTTP ' + res.status);
            var stderr = (res.body && res.body.stderr) || '';

            console.error('[RESTART] failed:', res.body);
            showToast('❌ Restart failed: ' + msg, 'error', 12000);

            if (stderr) {
                console.warn('[RESTART] stderr:\n' + stderr);
            }
            return;
        }

        var d = res.body;

        showToast(
            '✅ Extractor restarted in ' + (d.elapsed || 0).toFixed(1) + 's' +
            ' — ' + d.endpoint_count + ' endpoints',
            'success',
            10000
        );

        // ★★★ Response-এও flag reset (double safety)
        if (typeof extractorReady !== 'undefined') {
            extractorReady = false;
        }
        if (typeof extractorAutoStarted !== 'undefined') {
            extractorAutoStarted = false;
        }

        // ★★★ Watcher আবার চালু — যাতে নতুন extractor ready হলে toast আসে
        if (typeof startExtractorWatcher === 'function') {
            startExtractorWatcher();
        }
    })
    .catch(function(err) {
        showToast('❌ Restart error: ' + err.message, 'error', 12000);
        console.error('[RESTART] exception:', err);
    })
    .finally(function() {
        // ── Countdown timer বন্ধ
        clearInterval(countdownInterval);

        // ── Button state reset
        if (btn) {
            btn.classList.remove('loading');
            btn.disabled = false;
            btn.textContent = '🔁 Restart Extractor';
        }
    });
}

		function logout(){ fetch('/api/logout', {method:'POST'}).finally(function(){ localStorage.removeItem('token'); localStorage.removeItem('role'); localStorage.removeItem('locked'); localStorage.removeItem('user_id'); window.location.href='/login'; }); }

		function openTab(evt, tabName){ document.querySelectorAll('.tab-content').forEach(function(el){ el.classList.remove('active'); }); document.querySelectorAll('.tab-btn').forEach(function(el){ el.classList.remove('active'); }); document.getElementById(tabName).classList.add('active'); evt.currentTarget.classList.add('active'); }

		function hideNonAdminActions() {
			if(!isAdmin) {
				document.querySelectorAll('#accountsBody tr').forEach(function(row) {
					var select = row.querySelector('.step-select'); if(select) select.style.display = 'none';
					var startBtn = row.querySelector('.btn-action-start'); if(startBtn) startBtn.style.display = 'none';
					var stopBtn = row.querySelector('.btn-action-stop'); if(stopBtn) stopBtn.style.display = 'none';
				});
				document.querySelector(".btn-auto").style.display = "none";
				document.querySelector(".btn-stop").style.display = "none";
				document.querySelector("#globalStepSelect").style.display = "none";
			}
		}

		document.addEventListener('focusin', function(e) { if(e.target.closest('#accountsTable') && (e.target.tagName==='INPUT'||e.target.tagName==='SELECT')) stopPolling(); });
		document.addEventListener('focusout', function(e) { if(e.target.closest('#accountsTable') && (e.target.tagName==='INPUT'||e.target.tagName==='SELECT')) setTimeout(startPolling,500); });

		renderHeaders(); fetchUsers(); fetchAccounts(); startPolling(); hideNonAdminActions();
	</script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, html)
}

// ============================================================
// ১৩. ফাইল আপলোড হ্যান্ডলার
// ============================================================

func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := getUserFromContext(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	path := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) != 4 || parts[0] != "api" || parts[1] != "accounts" || parts[3] != "files" {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}
	accountID := parts[2]

	acc := storage.GetAccount(accountID)
	if acc == nil {
		http.Error(w, "Account not found", http.StatusNotFound)
		return
	}
	if claims.Role != "admin" && acc.UserID != claims.UserID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if claims.Locked {
		http.Error(w, "Account locked", http.StatusForbidden)
		return
	}

	// ★ ফোন নাম্বার ব্যবহার করুন ডিরেক্টরির জন্য
	phone := acc.Phone
	if phone == "" {
		http.Error(w, "Account has no phone number", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		uploadDir := filepath.Join("uploads", phone) // ← phone ব্যবহার
		files := []string{}
		if entries, err := os.ReadDir(uploadDir); err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					files = append(files, e.Name())
				}
			}
		}
		// ★ অ্যাকাউন্টের UploadFiles আপডেট করুন (যদি চান)
		storage.mu.Lock()
		for i := range storage.Accounts {
			if storage.Accounts[i].ID == accountID {
				storage.Accounts[i].UploadFiles = files
				storage.saveLocked()
				break
			}
		}
		storage.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"files": files})

	case http.MethodPost:
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "File missing", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// চেক করুন সর্বোচ্চ ৪টি ফাইল
		if len(acc.UploadFiles) >= 4 {
			http.Error(w, "Maximum 4 files allowed", http.StatusBadRequest)
			return
		}

		uploadDir := filepath.Join("uploads", phone) // ← phone ব্যবহার
		if err := os.MkdirAll(uploadDir, 0755); err != nil {
			http.Error(w, "Failed to create directory", http.StatusInternalServerError)
			return
		}

		// নতুন নাম তৈরি করুন (primary_ / secondary_)
		var newFilename string
		if len(acc.UploadFiles) == 0 {
			newFilename = "primary_" + header.Filename
		} else {
			count := len(acc.UploadFiles)
			newFilename = fmt.Sprintf("secondary_%d_%s", count, header.Filename)
		}

		dstPath := filepath.Join(uploadDir, newFilename)
		dst, err := os.Create(dstPath)
		if err != nil {
			http.Error(w, "Failed to create file", http.StatusInternalServerError)
			return
		}
		defer dst.Close()
		if _, err := io.Copy(dst, file); err != nil {
			http.Error(w, "Failed to save file", http.StatusInternalServerError)
			return
		}

		// অ্যাকাউন্টের তালিকা আপডেট করুন
		storage.mu.Lock()
		for i := range storage.Accounts {
			if storage.Accounts[i].ID == accountID {
				storage.Accounts[i].UploadFiles = append(storage.Accounts[i].UploadFiles, newFilename)
				storage.saveLocked()
				break
			}
		}
		storage.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	case http.MethodDelete:
		filename := r.URL.Query().Get("file")
		if filename == "" {
			http.Error(w, "File name required", http.StatusBadRequest)
			return
		}
		// ফাইল ডিলিট করুন
		filePath := filepath.Join("uploads", phone, filename) // ← phone ব্যবহার
		os.Remove(filePath)

		// অ্যাকাউন্টের তালিকা থেকে সরান
		storage.mu.Lock()
		for i := range storage.Accounts {
			if storage.Accounts[i].ID == accountID {
				newList := []string{}
				for _, f := range storage.Accounts[i].UploadFiles {
					if f != filename {
						newList = append(newList, f)
					}
				}
				storage.Accounts[i].UploadFiles = newList
				storage.saveLocked()
				break
			}
		}
		storage.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ============================================================
// ১৪. অন্যান্য হ্যান্ডলার
// ============================================================

func adminResetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// ★★★ প্রথমে টাস্ক বন্ধ করুন ★★★
	tasksMu.Lock()
	if cancel, ok := runningTasks[req.ID]; ok {
		cancel()
		delete(runningTasks, req.ID)
		log.Printf("[RESET] Task stopped for account %s", req.ID)
	}
	tasksMu.Unlock()

	// টাস্ক থামার জন্য একটু অপেক্ষা
	time.Sleep(200 * time.Millisecond)

	acc := storage.GetAccount(req.ID)
	if acc == nil {
		http.Error(w, "Account not found", http.StatusNotFound)
		return
	}

	// OTP ক্লিয়ার (ব্যাকগ্রাউন্ডে)
	if acc.Phone != "" {
		go func(phone, ip string) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			clearOTPFromServer(ctx, phone, ip)
		}(acc.Phone, acc.IP)
	}

	storage.mu.Lock()
	defer storage.mu.Unlock()

	for i := range storage.Accounts {
		if storage.Accounts[i].ID == req.ID {
			// ★★★ শুধু অটোমেশন ডেটা ক্লিয়ার করুন ★★★
			// ফাইল, মিশন, কনফার্মেশন ইত্যাদি অপরিবর্তিত রাখুন

			storage.Accounts[i].OTP = ""
			storage.Accounts[i].OTPVerified = false
			storage.Accounts[i].SignToken = ""
			storage.Accounts[i].AccessToken = ""
			storage.Accounts[i].RequestID = ""
			storage.Accounts[i].ReserveToken = ""
			storage.Accounts[i].ReservationID = ""
			storage.Accounts[i].AppointmentID = ""
			storage.Accounts[i].PaymentLink = ""
			storage.Accounts[i].PayToken = ""
			storage.Accounts[i].OTPFetchedAt = nil
			storage.Accounts[i].PaymentLinkAt = nil
			storage.Accounts[i].UploadedFiles = nil
			// ★★★ এগুলো ক্লিয়ার করবেন না ★★★
			// storage.Accounts[i].ConfirmationID = ""    ← ❌ করবেন না
			// storage.Accounts[i].MissionID = ""         ← ❌ করবেন না
			// storage.Accounts[i].UploadFiles = []string{} ← ❌ করবেন না
			// storage.Accounts[i].UploadedFiles = []string{} ← ❌ করবেন না
			// storage.Accounts[i].FileUploadConfirmed = false ← ❌ করবেন না
			// storage.Accounts[i].UploadEnd = false      ← ❌ করবেন না
			// storage.Accounts[i].PaymentConfirm = false ← ❌ করবেন না
			// storage.Accounts[i].SlotOpen = false       ← ❌ করবেন না
			// storage.Accounts[i].Mission = ""           ← ❌ করবেন না
			// storage.Accounts[i].IvacCenter = ""        ← ❌ করবেন না
			// storage.Accounts[i].AppointmentDate = ""   ← ❌ করবেন না
			// storage.Accounts[i].AppointmentDates = []string{} ← ❌ করবেন না

			// ✅ শুধু স্ট্যাটাস রিসেট করুন
			storage.Accounts[i].Status = "idle"

			if err := storage.saveLocked(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			log.Printf("[RESET] Account %s reset (confirmation, mission & files preserved)", req.ID)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]bool{"success": true})
			return
		}
	}
	http.Error(w, "Account not found", http.StatusNotFound)
}

// adminResetSelectedHandler - নির্বাচিত অ্যাকাউন্টগুলো রিসেট করুন
func adminResetSelectedHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.IDs) == 0 {
		http.Error(w, "No account IDs provided", http.StatusBadRequest)
		return
	}

	var successCount int
	var failedIDs []string

	// 1️⃣ প্রথমে সব টাস্ক বন্ধ করুন
	for _, accountID := range req.IDs {
		tasksMu.Lock()
		if cancel, ok := runningTasks[accountID]; ok {
			cancel()
			delete(runningTasks, accountID)
			log.Printf("[RESET] Task stopped for account %s", accountID)
		}
		tasksMu.Unlock()
	}

	// 2️⃣ টাস্ক থামার জন্য অপেক্ষা
	time.Sleep(200 * time.Millisecond)

	// 3️⃣ অ্যাকাউন্ট রিসেট করুন (শুধু অটোমেশন ডেটা ক্লিয়ার করবে)
	storage.mu.Lock()
	defer storage.mu.Unlock()

	for _, accountID := range req.IDs {
		var found bool
		for i := range storage.Accounts {
			if storage.Accounts[i].ID == accountID {
				found = true

				// OTP ক্লিয়ার (ব্যাকগ্রাউন্ডে)
				if phone := storage.Accounts[i].Phone; phone != "" {
					go func(phone, ip string) {
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer cancel()
						clearOTPFromServer(ctx, phone, ip)
					}(storage.Accounts[i].Phone, storage.Accounts[i].IP)
				}

				// ★★★ শুধু অটোমেশন ডেটা ক্লিয়ার করুন ★★★
				// ফাইল, মিশন, কনফার্মেশন ইত্যাদি অপরিবর্তিত রাখুন

				storage.Accounts[i].OTP = ""
				storage.Accounts[i].OTPVerified = false
				storage.Accounts[i].SignToken = ""
				storage.Accounts[i].AccessToken = ""
				storage.Accounts[i].RequestID = ""
				storage.Accounts[i].ReserveToken = ""
				storage.Accounts[i].ReservationID = ""
				storage.Accounts[i].AppointmentID = ""
				storage.Accounts[i].PaymentLink = ""
				storage.Accounts[i].PayToken = ""
				storage.Accounts[i].OTPFetchedAt = nil
				storage.Accounts[i].PaymentLinkAt = nil
				storage.Accounts[i].UploadedFiles = nil
				// ★★★ ConfirmationID ও MissionID ক্লিয়ার করবেন না ★★★
				// storage.Accounts[i].ConfirmationID = ""    ← ❌ করবেন না
				// storage.Accounts[i].MissionID = ""         ← ❌ করবেন না

				// ★★★ ফাইল সম্পর্কিত সব ফিল্ড অপরিবর্তিত ★★★
				// storage.Accounts[i].UploadFiles = []string{}        ← ❌ করবেন না
				// storage.Accounts[i].UploadedFiles = []string{}     ← ❌ করবেন না
				// storage.Accounts[i].FileUploadConfirmed = false    ← ❌ করবেন না
				// storage.Accounts[i].UploadEnd = false              ← ❌ করবেন না
				// storage.Accounts[i].PaymentConfirm = false         ← ❌ করবেন না
				// storage.Accounts[i].SlotOpen = false               ← ❌ করবেন না
				// storage.Accounts[i].Mission = ""                   ← ❌ করবেন না
				// storage.Accounts[i].IvacCenter = ""                ← ❌ করবেন না
				// storage.Accounts[i].AppointmentDate = ""           ← ❌ করবেন না
				// storage.Accounts[i].AppointmentDates = []string{}  ← ❌ করবেন না

				// ✅ শুধু স্ট্যাটাস রিসেট করুন (যেন আবার অটোমেশন শুরু করতে পারে)
				storage.Accounts[i].Status = "idle"

				log.Printf("[RESET] Account %s reset (confirmation, mission & files preserved)", accountID)
				successCount++
				break
			}
		}
		if !found {
			failedIDs = append(failedIDs, accountID)
		}
	}

	if err := storage.saveLocked(); err != nil {
		http.Error(w, "Failed to save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"message":     fmt.Sprintf("Reset successful for %d accounts (confirmation, mission & files preserved)", successCount),
		"reset_count": successCount,
		"failed_ids":  failedIDs,
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "token", Value: "", Path: "/", MaxAge: -1})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func startConfigWatcher() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal("Failed to create Watcher ", err)
	}
	defer watcher.Close()
	err = watcher.Add(".")
	if err != nil {
		log.Fatal("Failed to monitor directory:", err)
	}
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Chmod) != 0 {
					base := filepath.Base(event.Name)
					if base == "data.json" {
						log.Println("[CONFIG] data.json changed, reloading...")
						time.Sleep(100 * time.Millisecond)
						err := storage.ReloadConfig()
						if err != nil {
							log.Printf("[CONFIG] Reload failed: %v", err)
						} else {
							log.Println("[CONFIG] ✅ Config reloaded")
						}
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("[CONFIG] Watcher error:", err)
			}
		}
	}()
	log.Println("[CONFIG] File watcher started")
}

// ============================================================
// ১৫. লগইন পেজ, API হ্যান্ডলার
// ============================================================

func loginHandler(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html><head><title>Login</title><meta charset="UTF-8"><style>body{background:#1e1e1e;color:#eee;font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;}#login{background:#2a2a2a;padding:30px;border-radius:10px;width:300px;}input{width:100%;padding:8px;margin:5px 0;background:#333;border:1px solid #555;color:#fff;border-radius:4px;}button{width:100%;padding:10px;background:#4CAF50;border:none;color:#fff;border-radius:4px;cursor:pointer;font-size:16px;}.error{color:#f44336;}h2{text-align:center;}</style></head>
<body><div id="login"><h2>🔐 Login</h2><div id="error" class="error"></div><input type="text" id="username" placeholder="Username"><input type="password" id="password" placeholder="Password"><button onclick="login()">Sign In</button></div>
<script>function login(){const u=document.getElementById('username').value,p=document.getElementById('password').value;fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})}).then(r=>r.json()).then(data=>{if(data.token){localStorage.setItem('token',data.token);localStorage.setItem('role',data.role);localStorage.setItem('locked',data.locked);localStorage.setItem('user_id',data.id);window.location.href='/';}else{document.getElementById('error').textContent=data.message||'Login failed';}}).catch(err=>document.getElementById('error').textContent='Network error');}</script></body></html>`
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, html)
}

func loginAPIRouter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	user := storage.GetUserByUsername(req.Username)
	if user == nil || !checkPasswordHash(req.Password, user.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	token, err := generateToken(*user)
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "token", Value: token, HttpOnly: true, Path: "/", MaxAge: 86400})
	json.NewEncoder(w).Encode(map[string]interface{}{"token": token, "role": user.Role, "id": user.ID, "locked": user.Locked})
}
func endpointsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// ?refresh=1 দিলে force refresh
		if r.URL.Query().Get("refresh") == "1" {
			if err := endpointCache.ForceRefresh(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"endpoints": endpointCache.All(),
			"count":     len(endpointCache.All()),
		})

	case http.MethodPost:
		if err := endpointCache.ForceRefresh(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"count":   len(endpointCache.All()),
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		storage.mu.Lock()
		defer storage.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(storage.Users)
	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Username == "" || req.Password == "" {
			http.Error(w, "Username and password required", http.StatusBadRequest)
			return
		}
		if storage.GetUserByUsername(req.Username) != nil {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
		role := req.Role
		if role != "admin" && role != "user" {
			role = "user"
		}
		user := User{ID: generateUserID(), Username: req.Username, Password: hashPassword(req.Password), Role: role, Locked: false, CreatedAt: time.Now()}
		if err := storage.AddUser(user); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func userByIDHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/users/")
	if id == "" {
		http.Error(w, "Missing user ID", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var req struct {
			Field string `json:"field"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var username, password, role string
		var locked *bool
		switch req.Field {
		case "username":
			username = req.Value
		case "password":
			password = req.Value
		case "role":
			role = req.Value
		case "locked":
			val := req.Value == "true"
			locked = &val
		default:
			http.Error(w, "Invalid field", http.StatusBadRequest)
			return
		}
		if err := storage.UpdateUser(id, username, password, role, locked); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	case http.MethodDelete:
		if err := storage.DeleteUser(id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func adminAccountsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	storage.mu.Lock()
	defer storage.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(storage.Accounts)
}

func adminSaveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Phone      string `json:"phone"`
		Password   string `json:"password"`
		IP         string `json:"ip"`
		OTP        string `json:"otp"`
		UserID     string `json:"user_id"`
		Mission    string `json:"mission"`
		IvacCenter string `json:"ivac_center"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Phone == "" || req.Password == "" {
		http.Error(w, "Phone and Password required", http.StatusBadRequest)
		return
	}
	if req.UserID == "" {
		http.Error(w, "User ID required", http.StatusBadRequest)
		return
	}
	if storage.GetUserByID(req.UserID) == nil {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}
	acc := Account{
		ID:            generateAccountID(),
		UserID:        req.UserID,
		Phone:         req.Phone,
		Password:      req.Password,
		IP:            req.IP,
		OTP:           req.OTP,
		Status:        "idle",
		SignToken:     "",
		AccessToken:   "",
		RequestID:     "",
		ReserveToken:  "",
		ReservationID: "",
		AppointmentID: "",
		PaymentLink:   "",
		Mission:       req.Mission,
		IvacCenter:    req.IvacCenter,
	}
	if err := storage.AddAccount(acc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func adminUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID    string `json:"id"`
		Field string `json:"field"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := storage.UpdateAccountField(req.ID, req.Field, req.Value); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if req.Field == "otp" {
		updatedAcc := storage.GetAccount(req.ID)
		if updatedAcc != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if req.Value != "" {
				saveOTPToExternal(ctx, updatedAcc.Phone, req.Value, updatedAcc.IP)
			} else {
				go clearOTPFromServer(ctx, updatedAcc.Phone, updatedAcc.IP)
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func adminDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := storage.DeleteAccount(req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func adminDeleteAllHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := storage.DeleteAllAccounts(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func adminClearOTPHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	acc := storage.GetAccount(req.ID)
	if acc == nil {
		http.Error(w, "Account not found", http.StatusNotFound)
		return
	}
	if err := storage.UpdateAccountField(req.ID, "otp", ""); err != nil {
		http.Error(w, "Failed to clear local OTP: "+err.Error(), http.StatusInternalServerError)
		return
	}
	urlStr := fmt.Sprintf("https://hyperslot-otp-358970714333.us-central1.run.app/otp/remove/?phone=%s", acc.Phone)
	ctx := context.Background()
	resp, err := doRequestWithRetry(ctx, "GET", urlStr, nil, map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}, "")
	if err != nil {
		log.Printf("[WARN] Clear OTP external call failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Local OTP cleared (external call failed)"})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 404 {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[WARN] Clear OTP external API returned %d: %s", resp.StatusCode, string(body))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": fmt.Sprintf("Local OTP cleared, external API returned %d", resp.StatusCode)})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "OTP cleared successfully"})
}

func userAccountsHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := getUserFromContext(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		accounts := storage.GetAccountsByUser(claims.UserID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(accounts)
	case http.MethodPost:
		if claims.Locked {
			http.Error(w, "Account locked", http.StatusForbidden)
			return
		}
		var req struct {
			Phone         string `json:"phone"`
			Password      string `json:"password"`
			AppointmentID string `json:"appointment_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Phone == "" || req.Password == "" {
			http.Error(w, "Phone and Password required", http.StatusBadRequest)
			return
		}
		acc := Account{
			ID:            generateAccountID(),
			UserID:        claims.UserID,
			Phone:         req.Phone,
			Password:      req.Password,
			IP:            "",
			OTP:           "",
			Status:        "idle",
			AppointmentID: req.AppointmentID,
		}
		if err := storage.AddAccount(acc); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func userAccountByIDHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/user/accounts/")
	if id == "" {
		http.Error(w, "Missing account ID", http.StatusBadRequest)
		return
	}
	claims, ok := getUserFromContext(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	acc := storage.GetAccount(id)
	if acc == nil {
		http.Error(w, "Account not found", http.StatusNotFound)
		return
	}
	if acc.UserID != claims.UserID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if claims.Locked {
		http.Error(w, "Account locked", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var req struct {
			Field string `json:"field"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Field != "phone" && req.Field != "password" && req.Field != "appointment_id" && req.Field != "otp" {
			http.Error(w, "Field not editable", http.StatusBadRequest)
			return
		}
		if err := storage.UpdateAccountField(id, req.Field, req.Value); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if req.Field == "otp" {
			updatedAcc := storage.GetAccount(id)
			if updatedAcc != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if req.Value != "" {
					saveOTPToExternal(ctx, updatedAcc.Phone, req.Value, updatedAcc.IP)
				} else {
					go clearOTPFromServer(ctx, updatedAcc.Phone, updatedAcc.IP)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	case http.MethodDelete:
		if err := storage.DeleteAccount(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func adminActionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID   string `json:"id"`
		Step int    `json:"step"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	action := strings.TrimPrefix(r.URL.Path, "/api/")
	switch action {
	case "start", "auto":
		go runAutomation(req.ID, req.Step)
	case "stop":
		stopAutomation(req.ID)
	default:
		http.Error(w, "Unknown action", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func adminAutoAllHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
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
	for _, id := range ids {
		go runAutomation(id, req.Step)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": fmt.Sprintf("Auto started for %d accounts from step %d", len(ids), req.Step)})
}

func adminStopAllHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tasksMu.Lock()
	for id, cancel := range runningTasks {
		cancel()
		delete(runningTasks, id)
		storage.UpdateAccountField(id, "status", "stopped")
	}
	tasksMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "All tasks stopped"})
}

// adminAutoSelectedHandler - নির্বাচিত অ্যাকাউন্টগুলোর জন্য অটোমেশন চালু
func adminAutoSelectedHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IDs  []string `json:"ids"`
		Step int      `json:"step"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.IDs) == 0 {
		http.Error(w, "No account IDs provided", http.StatusBadRequest)
		return
	}
	for _, id := range req.IDs {
		go runAutomation(id, req.Step)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Auto started for %d accounts from step %d", len(req.IDs), req.Step),
	})
}

// adminStopSelectedHandler - নির্বাচিত অ্যাকাউন্টগুলো বন্ধ করুন
func adminStopSelectedHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.IDs) == 0 {
		http.Error(w, "No account IDs provided", http.StatusBadRequest)
		return
	}
	tasksMu.Lock()
	for _, id := range req.IDs {
		if cancel, ok := runningTasks[id]; ok {
			cancel()
			delete(runningTasks, id)
			storage.UpdateAccountField(id, "status", "stopped")
		}
	}
	tasksMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Stopped %d accounts", len(req.IDs)),
	})
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	storage.mu.Lock()
	defer storage.mu.Unlock()
	for key, val := range req {
		switch key {
		case "retry_count":
			if v, ok := val.(float64); ok {
				storage.Config.RetryCount = int(v)
			}
		case "retry_delay_sec":
			if v, ok := val.(float64); ok {
				storage.Config.RetryDelaySec = int(v)
			}
		case "concurrency":
			if v, ok := val.(float64); ok {
				storage.Config.Concurrency = int(v)
			}
		case "signin_concurrency":
			if v, ok := val.(float64); ok {
				storage.Config.SigninConcurrency = int(v)
			}
		case "delay_sec":
			if v, ok := val.(float64); ok {
				storage.Config.DelaySec = int(v)
			}
		case "reserve_retry_delay":
			if v, ok := val.(float64); ok {
				storage.Config.ReserveRetryDelay = int(v)
			}
		case "enable_retry":
			if v, ok := val.(bool); ok {
				storage.Config.EnableRetry = v
			}
		case "token_retry_count":
			if v, ok := val.(float64); ok {
				storage.Config.TokenRetryCount = int(v)
			}
		case "token_retry_delay_sec":
			if v, ok := val.(float64); ok {
				storage.Config.TokenRetryDelaySec = int(v)
			}
		case "token_enable_retry":
			if v, ok := val.(bool); ok {
				storage.Config.TokenEnableRetry = v
			}
		case "enable_warmup":
			if v, ok := val.(bool); ok {
				storage.Config.EnableWarmup = v
			}
		}
	}
	if err := storage.saveLocked(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// ============================================================
// extractorRestartHandler — Extractor প্রসেস সম্পূর্ণ restart করে
// ============================================================
//
// restart-extractor.ps1 script invoke করে, যেটা:
//
//	① পুরোনো extractor (port 1111) kill করে
//	② নতুন extractor spawn করে
//	③ port ready হওয়া পর্যন্ত wait করে
//
// Script synchronous — ready/timeout/error হলে return করে।
func extractorRestartHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	scriptPath := os.Getenv("EXTRACTOR_RESTART_PS1")
	if scriptPath == "" {
		// Fallback: panel এর CWD থেকে এক ধাপ উপরে
		cwd, _ := os.Getwd()
		scriptPath = filepath.Join(filepath.Dir(cwd), "restart-extractor.ps1")
	}

	if _, err := os.Stat(scriptPath); err != nil {
		log.Printf("[RESTART] ❌ script not found: %s", scriptPath)
		http.Error(w,
			"restart-extractor.ps1 not found at: "+scriptPath+
				" (set EXTRACTOR_RESTART_PS1 env var)",
			http.StatusInternalServerError)
		return
	}

	log.Printf("[RESTART] ▶ invoking %s", scriptPath)

	// সর্বোচ্চ 3 মিনিট wait (60s port wait + buffer)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "powershell.exe",
			"-ExecutionPolicy", "Bypass",
			"-NoProfile",
			"-File", scriptPath,
		)
	} else {
		cmd = exec.CommandContext(ctx, "pwsh",
			"-File", scriptPath,
		)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start)

	outStr := stdout.String()
	errStr := stderr.String()

	log.Printf("[RESTART] script done in %.1fs (err=%v)", elapsed.Seconds(), err)
	if outStr != "" {
		log.Printf("[RESTART] stdout:\n%s", outStr)
	}
	if errStr != "" {
		log.Printf("[RESTART] stderr:\n%s", errStr)
	}

	if err != nil {
		log.Printf("[RESTART] ❌ script failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
			"stdout":  outStr,
			"stderr":  errStr,
			"elapsed": elapsed.Seconds(),
		})
		return
	}

	// সফল → Panel cache refresh
	endpointCount := 0
	if err := endpointCache.ForceRefresh(); err != nil {
		log.Printf("[RESTART] ⚠️ endpoint cache refresh: %v", err)
	} else {
		endpointCount = len(endpointCache.All())
	}

	secCache.mu.Lock()
	secCache.headers = make(map[string]string)
	secCache.fetchedAt = time.Time{}
	secCache.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":        true,
		"endpoint_count": endpointCount,
		"elapsed":        elapsed.Seconds(),
		"message":        "extractor restarted",
	})
}

// ============================================================
// ১৬. main()
// ============================================================

func main() {
	var (
		extractorURLFlag = flag.String("extractor-url", "",
			"Extractor HTTP server URL (default: env EXTRACTOR_URL or http://127.0.0.1:1111)")
		panelPortFlag = flag.String("port", ":8080",
			"Panel HTTP server listen address")
		extractorMaxWait = flag.Duration("extractor-max-wait", 30*time.Minute,
			"Max time to wait for extractor")
	)
	flag.Parse()

	dir, _ := os.Getwd()
	log.Printf("[DEBUG] Current working directory: %s", dir)

	// ═══════════════════════════════════════════════════════════
	// ★ Extractor URL resolve
	// ═══════════════════════════════════════════════════════════
	extractorURL := *extractorURLFlag
	if extractorURL == "" {
		extractorURL = os.Getenv("EXTRACTOR_URL")
	}
	if extractorURL == "" {
		extractorURL = "http://127.0.0.1:1111"
	}

	// ★★★ NEW — global set (fetchSecurityHeaders এইটা ব্যবহার করে) ★★★
	extractorBaseURL = strings.TrimRight(extractorURL, "/")

	// ★ Background-এ watcher চালু (blocking নয়!)
	go startExtractorWatcher(extractorURL, *extractorMaxWait)

	storage = NewStorage("data.json")
	if err := storage.Load(); err != nil {
		log.Printf("[ERROR] Load failed: %v", err)
	} else {
		log.Printf("[DEBUG] Load successful, %d accounts, %d users", len(storage.Accounts), len(storage.Users))
	}
	go startConfigWatcher()

	os.MkdirAll("uploads", 0755)
	go startCaptchaSync()
	// ═══════════════════════════════════════════════════════════
	// HTTP routes
	// ═══════════════════════════════════════════════════════════
	http.HandleFunc("/api/endpoints", adminOnly(endpointsHandler))

	// ★ নতুন extractor endpoints
	http.HandleFunc("/api/extractor/status", adminOnly(extractorStatusHandler))
	http.HandleFunc("/api/extractor/stream", adminOnly(extractorReadyStreamHandler))
	http.HandleFunc("/api/extractor/autostart", adminOnly(extractorAutoStartHandler))
	http.HandleFunc("/api/extractor/restart", adminOnly(extractorRestartHandler))

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/api/auth/login", loginAPIRouter)
	http.HandleFunc("/", adminDashboardHandler)

	http.HandleFunc("/api/accounts", adminOnly(adminAccountsHandler))
	http.HandleFunc("/api/save", adminOnly(adminSaveHandler))
	http.HandleFunc("/api/update", adminOnly(adminUpdateHandler))
	http.HandleFunc("/api/delete", adminOnly(adminDeleteHandler))
	http.HandleFunc("/api/deleteall", adminOnly(adminDeleteAllHandler))
	http.HandleFunc("/api/clearotp", adminOnly(adminClearOTPHandler))
	http.HandleFunc("/api/config", adminOnly(configHandler))
	http.HandleFunc("/api/reset", adminOnly(adminResetHandler))

	http.HandleFunc("/api/start", adminOnly(adminActionHandler))
	http.HandleFunc("/api/stop", adminOnly(adminActionHandler))
	http.HandleFunc("/api/auto", adminOnly(adminActionHandler))
	http.HandleFunc("/api/autoall", adminOnly(adminAutoAllHandler))
	http.HandleFunc("/api/stopall", adminOnly(adminStopAllHandler))
	http.HandleFunc("/api/autoselected", adminOnly(adminAutoSelectedHandler))
	http.HandleFunc("/api/stopselected", adminOnly(adminStopSelectedHandler))
	http.HandleFunc("/api/user/accounts", authMiddleware(userAccountsHandler))
	http.HandleFunc("/api/user/accounts/", authMiddleware(userAccountByIDHandler))

	http.HandleFunc("/api/accounts/", authMiddleware(uploadFileHandler))
	http.HandleFunc("/api/resetselected", adminOnly(adminResetSelectedHandler))
	http.HandleFunc("/api/users", adminOnly(usersHandler))
	http.HandleFunc("/api/users/", adminOnly(userByIDHandler))
	http.HandleFunc("/api/captcha/sync-stats", adminOnly(captchaSyncStatsHandler))
	http.HandleFunc("/api/logout", logoutHandler)

	port := *panelPortFlag
	if !strings.HasPrefix(port, ":") {
		port = ":" + port
	}
	log.Printf("🚀 Panel server started at http://localhost%s", port)
	log.Printf("⏳ Panel is up. Waiting for extractor in background...")
	startTunnel()
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
