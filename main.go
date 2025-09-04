package main

import (
	"archive/zip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// Configuration structure
type Config struct {
	Server struct {
		Port      string `json:"port"`
		Host      string `json:"host"`
		CertFile  string `json:"certFile,omitempty"`
		KeyFile   string `json:"keyFile,omitempty"`
		AuditFile string `json:"auditFile,omitempty"`
		AutoTLS   bool   `json:"autoTLS,omitempty"`
		AcmeEmail string `json:"acmeEmail,omitempty"`
	} `json:"server"`
	Admin struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Comment  string `json:"comment,omitempty"`
	} `json:"admin"`
	JWT struct {
		ExpiryHours int    `json:"expiryHours"`
		Comment     string `json:"comment,omitempty"`
	} `json:"jwt"`
	Storage struct {
		Root    string `json:"root"`
		Comment string `json:"comment,omitempty"`
	} `json:"storage"`
	Features struct {
		AutoCleanTrash     bool   `json:"autoCleanTrash"`
		TrashRetentionDays int    `json:"trashRetentionDays"`
		MaxUploadSize      string `json:"maxUploadSize"`
		Comment            string `json:"comment,omitempty"`
	} `json:"features"`
}

// Global config instance
var appConfig Config

// storageRoot is the root directory for storing files.
var storageRoot string
var publicDir string

// meta & special dirs
var metaRoot string
var uploadsDir string
var versionsDir string
var trashDir string
var usersIndexPath string
var jwtSecretPath string
var usersDir string
var convertCacheDir string

var (
	sharesIndexPath   string
	versionsIndexPath string
	trashIndexPath    string
	filesIndexPath    string
)

var metaMu sync.Mutex
var jwtSecret []byte

// audit
var auditPath string
var auditMu sync.Mutex

type AuditEntry struct {
	ID     int64  `json:"id"`
	User   string `json:"user"`
	Action string `json:"action"`
	Target string `json:"target"`
	Type   string `json:"type,omitempty"`
	Size   int64  `json:"size,omitempty"`
	TS     int64  `json:"ts"`
}

func appendAudit(user, action, target, ftype string, size int64) {
	if auditPath == "" {
		return
	}
	if ftype == "" && target != "" {
		ext := strings.ToLower(filepath.Ext(target))
		if ext != "" {
			ftype = strings.TrimPrefix(ext, ".")
		} else {
			if strings.HasSuffix(target, "/") {
				ftype = "dir"
			} else {
				ftype = "file"
			}
		}
	}
	ent := AuditEntry{ID: time.Now().UnixNano(), User: user, Action: action, Target: target, Type: ftype, Size: size, TS: time.Now().Unix()}
	b, _ := json.Marshal(ent)
	auditMu.Lock()
	defer auditMu.Unlock()
	f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		_, _ = f.Write(append(b, '\n'))
		_ = f.Close()
	}
}

// User & auth
type User struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	Salt     string `json:"salt"`
	PassHash string `json:"passHash"`
	Created  int64  `json:"created"`
	Approved bool   `json:"approved"`
}

type UsersIndex map[string]User // username -> user

type jwtClaims struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Exp  int64  `json:"exp"`
}

func main() {
	// Load config.json if exists
	cfgPath := filepath.Join(".", "config.json")
	if b, err := os.ReadFile(cfgPath); err == nil {
		_ = json.Unmarshal(b, &appConfig)
	}

	// Resolve storage root: config > env STORAGE_ROOT > default
	rootFromCfg := strings.TrimSpace(appConfig.Storage.Root)
	if rootFromCfg == "" {
		rootFromCfg = os.Getenv("STORAGE_ROOT")
	}
	if rootFromCfg == "" {
		// 默认改为使用当前 backend 目录下的 data/storage
		rootFromCfg = filepath.Join("data", "storage")
	}
	abs, err := filepath.Abs(rootFromCfg)
	if err != nil {
		log.Fatalf("resolve storage path: %v", err)
	}
	storageRoot = abs
	if err := os.MkdirAll(storageRoot, 0755); err != nil {
		log.Fatalf("create storage root: %v", err)
	}

	pub, err := filepath.Abs(filepath.Join("public"))
	if err != nil {
		log.Fatalf("resolve public path: %v", err)
	}
	publicDir = pub

	// prepare meta dirs/files
	if err := ensureMetaPaths(); err != nil {
		log.Fatalf("init meta paths: %v", err)
	}

	mux := http.NewServeMux()
	// API routes
	mux.HandleFunc("/healthz", handleHealth)
	// auth
	mux.HandleFunc("/api/login", withCORS(handleLogin))
	// 注册与管理员审核
	mux.HandleFunc("/api/register", withCORS(handleRegister))
	mux.HandleFunc("/api/admin/registrations", withCORS(withAuth(handleAdminRegistrations)))
	mux.HandleFunc("/api/admin/approve", withCORS(withAuth(handleAdminApprove)))
	mux.HandleFunc("/api/admin/reject", withCORS(withAuth(handleAdminReject)))
	// 管理员：用户管理
	mux.HandleFunc("/api/admin/users", withCORS(withAuth(handleAdminUsersList)))
	mux.HandleFunc("/api/admin/users/disable", withCORS(withAuth(handleAdminUsersDisable)))
	mux.HandleFunc("/api/admin/users/enable", withCORS(withAuth(handleAdminUsersEnable)))
	mux.HandleFunc("/api/admin/users/delete", withCORS(withAuth(handleAdminUsersDelete)))
	// 新增：修改密码
	mux.HandleFunc("/api/password/change", withCORS(withAuth(handlePasswordChange)))

	// Protected APIs
	mux.HandleFunc("/api/files", withCORS(withAuth(handleListFiles)))
	mux.HandleFunc("/api/mkdir", withCORS(withAuth(handleMkdir)))
	mux.HandleFunc("/api/upload", withCORS(withAuth(handleUpload)))
	// chunked upload
	mux.HandleFunc("/api/upload/init", withCORS(withAuth(handleUploadInit)))
	mux.HandleFunc("/api/upload/chunk", withCORS(withAuth(handleUploadChunk)))
	mux.HandleFunc("/api/upload/status", withCORS(withAuth(handleUploadStatus)))
	mux.HandleFunc("/api/upload/complete", withCORS(withAuth(handleUploadComplete)))
	// versions
	mux.HandleFunc("/api/versions", withCORS(withAuth(handleVersionsList)))
	mux.HandleFunc("/api/versions/restore", withCORS(withAuth(handleVersionsRestore)))
	mux.HandleFunc("/api/versions/delete", withCORS(withAuth(handleVersionsDelete)))
	mux.HandleFunc("/api/versions/batch/restore", withCORS(withAuth(handleVersionsBatchRestore)))
	mux.HandleFunc("/api/versions/batch/delete", withCORS(withAuth(handleVersionsBatchDelete)))
	// download/delete/rename/move
	mux.HandleFunc("/api/download", withCORS(withAuth(handleDownload)))
	mux.HandleFunc("/api/convert/pdf", withCORS(withAuth(handleConvertPDF)))
	mux.HandleFunc("/api/batch/download", withCORS(withAuth(handleBatchDownload)))
	mux.HandleFunc("/api/batch/delete", withCORS(withAuth(handleBatchDelete)))
	// 搜索
	mux.HandleFunc("/api/search", withCORS(withAuth(handleSearch)))
	mux.HandleFunc("/api/batch/move", withCORS(withAuth(handleBatchMove)))
	mux.HandleFunc("/api/file", withCORS(withAuth(handleDelete)))
	mux.HandleFunc("/api/rename", withCORS(withAuth(handleRename)))
	mux.HandleFunc("/api/move", withCORS(withAuth(handleMove)))
	// trash
	mux.HandleFunc("/api/trash", withCORS(withAuth(handleTrashList)))
	mux.HandleFunc("/api/trash/restore", withCORS(withAuth(handleTrashRestore)))
	mux.HandleFunc("/api/trash/delete", withCORS(withAuth(handleTrashDelete)))
	mux.HandleFunc("/api/trash/batch/restore", withCORS(withAuth(handleTrashBatchRestore)))
	mux.HandleFunc("/api/trash/batch/delete", withCORS(withAuth(handleTrashBatchDelete)))
	// shares (protected to manage, but public download page below)
	mux.HandleFunc("/api/share/create", withCORS(withAuth(handleShareCreate)))
	mux.HandleFunc("/api/share/list", withCORS(withAuth(handleShareList)))
	mux.HandleFunc("/api/share/revoke", withCORS(withAuth(handleShareRevoke)))
	// public share download (no auth)
	mux.HandleFunc("/s/", handleShareDownload)

	// Audit list API (admin)
	mux.HandleFunc("/api/audit/list", withCORS(withAuth(handleAuditList)))

	// Static files (frontend)
	fs := http.FileServer(http.Dir(publicDir))
	mux.Handle("/", fs)

	// Port: config > env PORT > default
	port := strings.TrimSpace(appConfig.Server.Port)
	if port == "" {
		port = os.Getenv("PORT")
	}
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	// determine audit log path
	if appConfig.Server.AuditFile != "" {
		auditPath = appConfig.Server.AuditFile
	} else {
		auditPath = filepath.Join(metaRoot, "audit.log")
	}
	log.Printf("HaCloud backend starting...\nStorage: %s\nPublic: %s\nAudit: %s\n", storageRoot, publicDir, auditPath)
	// 1) 手动证书路径
	if appConfig.Server.CertFile != "" && appConfig.Server.KeyFile != "" {
		log.Printf("TLS enabled on https://%s%s (cert: %s)\n", appConfig.Server.Host, addr, appConfig.Server.CertFile)
		go func() {
			if err := http.ListenAndServeTLS(addr, appConfig.Server.CertFile, appConfig.Server.KeyFile, logRequest(mux)); err != nil {
				log.Printf("TLS server error: %v", err)
			}
		}()
	}
	// 2) AutoTLS（Let's Encrypt）
	if appConfig.Server.AutoTLS && appConfig.Server.Host != "" {
		cacheDir := filepath.Join(storageRoot, "_certcache")
		mgr := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(cacheDir),
			HostPolicy: autocert.HostWhitelist(appConfig.Server.Host),
			Email:      appConfig.Server.AcmeEmail,
		}
		go http.ListenAndServe(":80", mgr.HTTPHandler(nil))
		log.Printf("AutoTLS enabled for host %s (ACME)\n", appConfig.Server.Host)
		go func() {
			srv := &http.Server{Addr: ":443", Handler: logRequest(mux), TLSConfig: mgr.TLSConfig()}
			if err := srv.ListenAndServeTLS("", ""); err != nil {
				log.Printf("AutoTLS server error: %v", err)
			}
		}()
	}
	// HTTP 回退
	log.Printf("Listening on http://localhost:%s\n", port)
	go func() {
		if err := http.ListenAndServe(addr, logRequest(mux)); err != nil {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// GUI 构建：启动图形界面（阻塞主 goroutine）
	startGUI()
}

func handleAuditList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cl, ok := getUser(r)
	if !ok || cl.Role != "admin" {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	// limit param
	limStr := r.URL.Query().Get("limit")
	lim := 100
	if limStr != "" {
		if v, err := strconv.Atoi(limStr); err == nil && v > 0 {
			lim = v
		}
	}
	// read file
	auditMu.Lock()
	defer auditMu.Unlock()
	data, err := os.ReadFile(auditPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	// take last lim lines
	if len(lines) > lim {
		lines = lines[len(lines)-lim:]
	}
	entries := make([]AuditEntry, 0, len(lines))
	for _, ln := range lines {
		var e AuditEntry
		if json.Unmarshal([]byte(ln), &e) == nil {
			entries = append(entries, e)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].TS > entries[j].TS })
	writeJSON(w, http.StatusOK, entries)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// ===== Auth helpers =====

func withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		token := strings.TrimSpace(auth[len("Bearer "):])
		cl, err := parseJWT(token)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		// Ensure the user still exists and is approved (not disabled) on each request
		var users UsersIndex
		_ = loadJSON(usersIndexPath, &users)
		u, ok := users[cl.Sub]
		if !ok || !u.Approved {
			writeErr(w, http.StatusUnauthorized, "account disabled or not found")
			return
		}
		ctx := context.WithValue(r.Context(), ctxUserKey("user"), cl)
		next(w, r.WithContext(ctx))
	}
}

type ctxUserKey string

func getUser(r *http.Request) (jwtClaims, bool) {
	v := r.Context().Value(ctxUserKey("user"))
	if v == nil {
		return jwtClaims{}, false
	}
	cl, ok := v.(jwtClaims)
	return cl, ok
}

func base64urlEncode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

func base64urlDecode(s string) ([]byte, error) {
	// pad with '=' to multiple of 4
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(s)
}

func signJWT(cl jwtClaims) (string, error) {
	hdr := map[string]string{"alg": "HS256", "typ": "JWT"}
	hb, _ := json.Marshal(hdr)
	pb, _ := json.Marshal(cl)
	head := base64urlEncode(hb)
	pay := base64urlEncode(pb)
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(head + "." + pay))
	sig := mac.Sum(nil)
	return head + "." + pay + "." + base64urlEncode(sig), nil
}

func parseJWT(token string) (jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jwtClaims{}, errors.New("token format")
	}
	_, err := base64urlDecode(parts[0])
	if err != nil {
		return jwtClaims{}, err
	}
	pb, err := base64urlDecode(parts[1])
	if err != nil {
		return jwtClaims{}, err
	}
	sb, err := base64urlDecode(parts[2])
	if err != nil {
		return jwtClaims{}, err
	}
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, sb) {
		return jwtClaims{}, errors.New("bad signature")
	}
	var cl jwtClaims
	if err := json.Unmarshal(pb, &cl); err != nil {
		return jwtClaims{}, err
	}
	if cl.Exp > 0 && time.Now().Unix() > cl.Exp {
		return jwtClaims{}, errors.New("expired")
	}
	return cl, nil
}

func genSalt(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashPassword(password, salt string) string {
	// Simple iterative SHA-256 (MVP, replace with bcrypt in production)
	data := []byte(salt + ":" + password)
	for i := 0; i < 10000; i++ {
		h := sha256.Sum256(data)
		data = h[:]
	}
	return hex.EncodeToString(data)
}

func verifyPassword(password, salt, hash string) bool {
	return hashPassword(password, salt) == hash
}

// 新增：修改密码处理
func handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cl, ok := getUser(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if len(strings.TrimSpace(req.NewPassword)) < 6 {
		writeErr(w, http.StatusBadRequest, "new password too short")
		return
	}
	metaMu.Lock()
	defer metaMu.Unlock()
	var users UsersIndex
	_ = loadJSON(usersIndexPath, &users)
	u, ok := users[cl.Sub]
	if !ok {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if !verifyPassword(req.OldPassword, u.Salt, u.PassHash) {
		writeErr(w, http.StatusUnauthorized, "old password not match")
		return
	}
	salt, _ := genSalt(16)
	u.Salt = salt
	u.PassHash = hashPassword(req.NewPassword, salt)
	users[u.Username] = u
	if err := saveJSON(usersIndexPath, users); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	appendAudit(cl.Sub, "password_change", "", "", 0)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	metaMu.Lock()
	defer metaMu.Unlock()
	var users UsersIndex
	_ = loadJSON(usersIndexPath, &users)
	u, ok := users[req.Username]
	if !ok || !verifyPassword(req.Password, u.Salt, u.PassHash) {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if !u.Approved {
		writeErr(w, http.StatusForbidden, "not approved yet")
		return
	}
	exp := time.Now().Add(12 * time.Hour).Unix()
	tok, _ := signJWT(jwtClaims{Sub: u.Username, Role: u.Role, Exp: exp})
	// 审计
	appendAudit(u.Username, "login", "", "", 0)

	writeJSON(w, http.StatusOK, map[string]any{
		"token": tok,
		"user":  map[string]any{"username": u.Username, "role": u.Role},
		"exp":   exp,
	})
}

// 注册：普通用户提交注册，等待管理员审核
func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	uname := strings.TrimSpace(req.Username)
	if len(uname) < 3 || len(uname) > 32 {
		writeErr(w, http.StatusBadRequest, "invalid username length")
		return
	}
	// 仅允许字母、数字、下划线
	for _, ch := range uname {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' {
			continue
		}
		writeErr(w, http.StatusBadRequest, "invalid username characters")
		return
	}
	if len(req.Password) < 6 {
		writeErr(w, http.StatusBadRequest, "password too short")
		return
	}

	metaMu.Lock()
	defer metaMu.Unlock()
	var users UsersIndex
	_ = loadJSON(usersIndexPath, &users)
	if users == nil {
		users = UsersIndex{}
	}
	if _, exists := users[uname]; exists {
		writeErr(w, http.StatusConflict, "username exists")
		return
	}
	salt, _ := genSalt(16)
	u := User{Username: uname, Role: "user", Salt: salt, PassHash: hashPassword(req.Password, salt), Created: time.Now().Unix(), Approved: false}
	users[uname] = u
	if err := saveJSON(usersIndexPath, users); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// 管理员：获取待审核用户列表
func handleAdminRegistrations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cl, ok := getUser(r)
	if !ok || cl.Role != "admin" {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	metaMu.Lock()
	defer metaMu.Unlock()
	var users UsersIndex
	_ = loadJSON(usersIndexPath, &users)
	list := make([]map[string]any, 0)
	for _, u := range users {
		if u.Role == "user" && !u.Approved {
			list = append(list, map[string]any{"username": u.Username, "created": u.Created})
		}
	}
	// 排序：按创建时间
	sort.Slice(list, func(i, j int) bool { return list[i]["created"].(int64) < list[j]["created"].(int64) })
	writeJSON(w, http.StatusOK, list)
}

// 管理员：批准
func handleAdminApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cl, ok := getUser(r)
	if !ok || cl.Role != "admin" {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		writeErr(w, http.StatusBadRequest, "missing username")
		return
	}
	metaMu.Lock()
	defer metaMu.Unlock()
	var users UsersIndex
	_ = loadJSON(usersIndexPath, &users)
	u, exists := users[username]
	if !exists {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	u.Approved = true
	users[username] = u
	if err := saveJSON(usersIndexPath, users); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// 管理员：拒绝（删除未审批用户）
func handleAdminReject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cl, ok := getUser(r)
	if !ok || cl.Role != "admin" {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		writeErr(w, http.StatusBadRequest, "missing username")
		return
	}
	if username == "admin" {
		writeErr(w, http.StatusBadRequest, "cannot reject admin")
		return
	}
	metaMu.Lock()
	defer metaMu.Unlock()
	var users UsersIndex
	_ = loadJSON(usersIndexPath, &users)
	if _, exists := users[username]; !exists {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	delete(users, username)
	if err := saveJSON(usersIndexPath, users); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// 管理员：用户列表（仅普通用户）
func handleAdminUsersList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cl, ok := getUser(r)
	if !ok || cl.Role != "admin" {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	metaMu.Lock()
	defer metaMu.Unlock()
	var users UsersIndex
	_ = loadJSON(usersIndexPath, &users)
	list := make([]map[string]any, 0)
	for _, u := range users {
		if u.Role == "user" {
			list = append(list, map[string]any{
				"username": u.Username,
				"approved": u.Approved,
				"created":  u.Created,
			})
		}
	}
	// 按创建时间升序
	sort.Slice(list, func(i, j int) bool { return list[i]["created"].(int64) < list[j]["created"].(int64) })
	writeJSON(w, http.StatusOK, list)
}

// 管理员：禁用用户（Approved=false），并撤销其分享
func handleAdminUsersDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cl, ok := getUser(r)
	if !ok || cl.Role != "admin" {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		writeErr(w, http.StatusBadRequest, "missing username")
		return
	}
	if username == "admin" {
		writeErr(w, http.StatusBadRequest, "cannot disable admin")
		return
	}
	// 更新用户状态
	metaMu.Lock()
	var users UsersIndex
	_ = loadJSON(usersIndexPath, &users)
	u, exists := users[username]
	if !exists {
		metaMu.Unlock()
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	u.Approved = false
	users[username] = u
	if err := saveJSON(usersIndexPath, users); err != nil {
		metaMu.Unlock()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	metaMu.Unlock()
	// 撤销用户的所有分享
	_ = disableUserShares(username)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// 管理员：启用用户（Approved=true）
func handleAdminUsersEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cl, ok := getUser(r)
	if !ok || cl.Role != "admin" {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		writeErr(w, http.StatusBadRequest, "missing username")
		return
	}
	if username == "admin" {
		writeErr(w, http.StatusBadRequest, "cannot enable admin")
		return
	}
	metaMu.Lock()
	defer metaMu.Unlock()
	var users UsersIndex
	_ = loadJSON(usersIndexPath, &users)
	u, exists := users[username]
	if !exists {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	u.Approved = true
	users[username] = u
	if err := saveJSON(usersIndexPath, users); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// 管理员：销户（删除用户、将其私有目录移入回收站、清理索引、撤销分享）
func handleAdminUsersDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cl, ok := getUser(r)
	if !ok || cl.Role != "admin" {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if username == "" {
		writeErr(w, http.StatusBadRequest, "missing username")
		return
	}
	if username == "admin" {
		writeErr(w, http.StatusBadRequest, "cannot delete admin")
		return
	}
	// 先尝试将 .users/<username> 目录移入回收站（若存在）
	rel := filepath.ToSlash(filepath.Join(".users", username))
	abs := filepath.Join(storageRoot, ".users", username)
	if st, err := os.Stat(abs); err == nil && st.IsDir() {
		if err := moveToTrash(abs, rel); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("move user home to trash: %v", err))
			return
		}
	}
	// 清理索引并撤销分享
	if err := cleanupUserIndexes(username); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := disableUserShares(username); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// 最后从用户索引删除
	metaMu.Lock()
	var users UsersIndex
	_ = loadJSON(usersIndexPath, &users)
	if _, ok := users[username]; !ok {
		metaMu.Unlock()
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	delete(users, username)
	if err := saveJSON(usersIndexPath, users); err != nil {
		metaMu.Unlock()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	metaMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// 撤销某用户创建的所有分享（置为 Disabled=true）
func disableUserShares(username string) error {
	metaMu.Lock()
	defer metaMu.Unlock()
	var shares SharesIndex
	_ = loadJSON(sharesIndexPath, &shares)
	changed := false
	for token, sh := range shares {
		if sh.CreatedBy == username && !sh.Disabled {
			sh.Disabled = true
			shares[token] = sh
			changed = true
		}
	}
	if changed {
		return saveJSON(sharesIndexPath, shares)
	}
	return nil
}

// 清理与某用户相关的 FilesIndex / VersionsIndex 项（.users/<username> 前缀）
func cleanupUserIndexes(username string) error {
	prefix := ".users/" + username
	metaMu.Lock()
	defer metaMu.Unlock()
	// FilesIndex
	{
		idx := FilesIndex{}
		_ = loadJSON(filesIndexPath, &idx)
		if len(idx) > 0 {
			for k := range idx {
				kk := filepath.ToSlash(k)
				if kk == prefix || strings.HasPrefix(kk, prefix+"/") {
					delete(idx, k)
				}
			}
			if err := saveJSON(filesIndexPath, idx); err != nil {
				return err
			}
		}
	}
	// VersionsIndex
	{
		vidx := VersionsIndex{}
		_ = loadJSON(versionsIndexPath, &vidx)
		if len(vidx) > 0 {
			for k := range vidx {
				kk := filepath.ToSlash(k)
				if kk == prefix || strings.HasPrefix(kk, prefix+"/") {
					delete(vidx, k)
				}
			}
			if err := saveJSON(versionsIndexPath, vidx); err != nil {
				return err
			}
		}
	}
	return nil
}

func withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func logRequest(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

type FileEntry struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	IsDir    bool      `json:"isDir"`
	Size     int64     `json:"size"`
	ModTime  time.Time `json:"modTime"`
	Uploader string    `json:"uploader,omitempty"`
}

func handleListFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	qpath := r.URL.Query().Get("path")
	abs, rel, err := resolvePath(r, storageRoot, qpath)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// If path is a file, return its metadata only
	fi, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, []FileEntry{})
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !fi.IsDir() {
		entry := FileEntry{Name: fi.Name(), Path: rel, IsDir: false, Size: fi.Size(), ModTime: fi.ModTime()}
		// 公共区：补充 uploader 便于前端前置拦截
		if detectOwnerFromRel(filepath.ToSlash(rel)) == "" {
			u := getUploaderForRel(rel)
			if u == "" {
				name := fi.Name()
				if strings.HasPrefix(name, "(") {
					if i := strings.Index(name, ") "); i >= 0 {
						u = name[1:i]
					}
				}
			}
			entry.Uploader = u
		}
		writeJSON(w, http.StatusOK, []FileEntry{entry})
		return
	}
	f, err := os.ReadDir(abs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// filter internal system dirs in root
	internal := map[string]struct{}{".meta": {}, ".uploads": {}, ".versions": {}, ".trash": {}, ".users": {}, ".convert-cache": {}}
	var list []FileEntry
	for _, e := range f {
		name := e.Name()
		if rel == "" { // only hide at root
			if _, ok := internal[name]; ok {
				continue
			}
		}
		info, _ := e.Info()
		childRel := filepath.ToSlash(filepath.Join(rel, name))
		fe := FileEntry{
			Name:    name,
			Path:    childRel,
			IsDir:   e.IsDir(),
			Size:    sizeOf(info),
			ModTime: info.ModTime(),
		}
		// 仅公共区返回 uploader（目录从索引获取；文件缺失索引时回退解析前缀）
		if detectOwnerFromRel(childRel) == "" {
			u := getUploaderForRel(childRel)
			if u == "" && !e.IsDir() {
				if strings.HasPrefix(name, "(") {
					if i := strings.Index(name, ") "); i >= 0 {
						u = name[1:i]
					}
				}
			}
			if u != "" {
				fe.Uploader = u
			}
		}
		list = append(list, fe)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].IsDir != list[j].IsDir {
			return list[i].IsDir // dirs first
		}
		return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name)
	})
	writeJSON(w, http.StatusOK, list)
}

func handleMkdir(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cl, _ := getUser(r)
	qpath := r.URL.Query().Get("path")
	name := r.URL.Query().Get("name")
	if name != "" {
		base := sanitizeFilename(name)
		if base == "." || base == ".." { // forbid weird names
			writeErr(w, http.StatusBadRequest, "invalid folder name")
			return
		}
		// 判断所属空间
		owner := ""
		{
			trim := strings.TrimPrefix(strings.TrimSpace(qpath), "/")
			if strings.HasPrefix(trim, "@me") {
				if cl.Sub != "" {
					owner = cl.Sub
				}
			}
			if owner == "" {
				owner = detectOwnerFromRel(filepath.ToSlash(filepath.Join(qpath, base)))
			}
		}
		targetName := base
		// 公共区加 (username) 前缀
		if owner == "" && cl.Sub != "" {
			prefix := fmt.Sprintf("(%s) ", cl.Sub)
			if !strings.HasPrefix(targetName, prefix) {
				targetName = prefix + targetName
			}
		}
		// 父目录路径
		absParent, _, err := resolvePath(r, storageRoot, qpath)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		// 公共区去重
		if owner == "" {
			targetName = uniqueFilenameInDir(absParent, targetName)
		}
		abs := filepath.Join(absParent, targetName)
		if err := os.MkdirAll(abs, 0755); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		// 计算相对路径并记录创建者
		_, rel, err := resolvePath(r, storageRoot, filepath.ToSlash(filepath.Join(qpath, targetName)))
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if cl.Sub != "" {
			setUploaderForRel(rel, cl.Sub)
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "name": targetName})
		return
	}
	abs, rel, err := resolvePath(r, storageRoot, qpath)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := os.MkdirAll(abs, 0755); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// 记录创建者（用于公共区权限）
	if cl.Sub != "" {
		setUploaderForRel(rel, cl.Sub)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	qpath := r.URL.Query().Get("path")
	absDir, _, err := resolvePath(r, storageRoot, qpath)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := os.MkdirAll(absDir, 0755); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Accept single file (field name: file)
	err = r.ParseMultipartForm(64 << 20) // 64MB memory threshold
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "missing file field")
		return
	}
	defer file.Close()
	filename := sanitizeFilename(header.Filename)

	cl, _ := getUser(r)
	// 根据路径判断私有/公共，并应用命名与版本策略
	// 判断所属空间：@me 视为当前用户的私有空间
	owner := ""
	{
		trim := strings.TrimPrefix(strings.TrimSpace(qpath), "/")
		if strings.HasPrefix(trim, "@me") {
			if cl.Sub != "" {
				owner = cl.Sub
			}
		}
		if owner == "" {
			owner = detectOwnerFromRel(filepath.ToSlash(filepath.Join(qpath, filename)))
		}
	}
	targetName := filename
	if owner == "" { // 公共区：为文件名前加“(username) ”前缀
		if cl.Sub != "" {
			prefix := fmt.Sprintf("(%s) ", cl.Sub)
			if !strings.HasPrefix(targetName, prefix) {
				targetName = prefix + targetName
			}
		}
	}
	absTarget := filepath.Join(absDir, targetName)
	// 计算用于版本与权限索引的相对路径
	_, relTarget, err := resolvePath(r, storageRoot, filepath.ToSlash(filepath.Join(qpath, targetName)))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, statErr := os.Stat(absTarget); statErr == nil { // 目标已存在
		if owner != "" { // 私有区：进行版本替换
			if err := saveVersion(absTarget, relTarget); err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			_ = os.Remove(absTarget)
		} else { // 公共区
			uploader := getUploaderForRel(relTarget)
			if cl.Sub != "" && uploader == cl.Sub { // 同一用户：版本替换
				if err := saveVersion(absTarget, relTarget); err != nil {
					writeErr(w, http.StatusInternalServerError, err.Error())
					return
				}
				_ = os.Remove(absTarget)
			} else {
				// 不同用户或未知元数据：为现有前缀名再追加去冲突后缀
				uniq := uniqueFilenameInDir(absDir, targetName)
				if uniq != targetName {
					targetName = uniq
					absTarget = filepath.Join(absDir, targetName)
					_, relTarget, _ = resolvePath(r, storageRoot, filepath.ToSlash(filepath.Join(qpath, targetName)))
				}
			}
		}
	}
	out, err := os.Create(absTarget)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer out.Close()
	if _, err := io.Copy(out, file); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// 记录上传者（用于公共区权限与后续版本判断）
	if cl.Sub != "" {
		setUploaderForRel(relTarget, cl.Sub)
	}
	fiUp, _ := os.Stat(absTarget)
	var upSize int64
	if fiUp != nil {
		upSize = fiUp.Size()
	}
	appendAudit(cl.Sub, "upload", relTarget, "file", upSize)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "name": targetName})
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	qpath := r.URL.Query().Get("path")
	abs, rel, err := resolvePath(r, storageRoot, qpath)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	fi, err := os.Stat(abs)
	if err != nil || fi.IsDir() {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(abs)))
	if cl, ok := getUser(r); ok {
		appendAudit(cl.Sub, "download", rel, "file", fi.Size())
	}
	http.ServeFile(w, r, abs)
}

func handleConvertPDF(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	qpath := r.URL.Query().Get("path")
	abs, rel, err := resolvePath(r, storageRoot, qpath)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	fi, err := os.Stat(abs)
	if err != nil || fi.IsDir() {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	lower := strings.ToLower(filepath.Ext(abs))
	if lower == ".pdf" { // 已是 PDF，直接回传
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"%s\"", filepath.Base(abs)))
		http.ServeFile(w, r, abs)
		return
	}
	supported := map[string]bool{".doc": true, ".docx": true, ".ppt": true, ".pptx": true, ".xls": true, ".xlsx": true}
	if !supported[lower] {
		writeErr(w, http.StatusBadRequest, "unsupported type for conversion")
		return
	}
	relSlash := filepath.ToSlash(rel)
	cachePDF := filepath.Join(convertCacheDir, relSlash+".pdf")
	if st, err := os.Stat(cachePDF); err == nil && !st.IsDir() {
		// 如果缓存比源文件新，则直接返回缓存
		srcInfo, e2 := os.Stat(abs)
		if e2 == nil && st.ModTime().After(srcInfo.ModTime()) {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"%s.pdf\"", filepath.Base(abs)))
			http.ServeFile(w, r, cachePDF)
			return
		}
	}
	if err := os.MkdirAll(filepath.Dir(cachePDF), 0755); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// 选择 soffice 可执行程序（多平台兼容与常见安装路径）
	var exePath string
	var candidates []string
	if runtime.GOOS == "windows" {
		candidates = []string{"soffice.com", "soffice.exe", `C:\\Program Files\\LibreOffice\\program\\soffice.com`, `C:\\Program Files\\LibreOffice\\program\\soffice.exe`, `C:\\Program Files (x86)\\LibreOffice\\program\\soffice.com`, `C:\\Program Files (x86)\\LibreOffice\\program\\soffice.exe`, `D:\\Program Files\\LibreOffice\\program\\soffice.com`, `D:\\Program Files\\LibreOffice\\program\\soffice.exe`}
	} else if runtime.GOOS == "darwin" {
		candidates = []string{"soffice", "/Applications/LibreOffice.app/Contents/MacOS/soffice"}
	} else {
		candidates = []string{"soffice", "libreoffice"}
	}
	for _, c := range candidates {
		if strings.Contains(c, string(os.PathSeparator)) || strings.HasPrefix(c, "/") || (runtime.GOOS == "windows" && strings.Contains(c, ":\\")) {
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				exePath = c
				break
			}
		} else {
			if lp, err := exec.LookPath(c); err == nil {
				exePath = lp
				break
			}
		}
	}
	if exePath == "" {
		writeErr(w, http.StatusInternalServerError, "convert failed: LibreOffice (soffice) not found; please install and add it to PATH")
		return
	}
	outDir := filepath.Dir(cachePDF)
	cmd := exec.Command(exePath, "--headless", "--convert-to", "pdf", "--outdir", outDir, abs)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		writeErr(w, http.StatusInternalServerError, "convert failed: please install LibreOffice/soffice and ensure it is in PATH")
		return
	}
	base := strings.TrimSuffix(filepath.Base(abs), filepath.Ext(abs)) + ".pdf"
	outPDF := filepath.Join(outDir, base)
	if outPDF != cachePDF {
		_ = os.MkdirAll(filepath.Dir(cachePDF), 0755)
		_ = os.Remove(cachePDF)
		if err := os.Rename(outPDF, cachePDF); err != nil {
			src, e1 := os.Open(outPDF)
			if e1 != nil {
				writeErr(w, http.StatusInternalServerError, e1.Error())
				return
			}
			defer src.Close()
			dst, e2 := os.Create(cachePDF)
			if e2 != nil {
				writeErr(w, http.StatusInternalServerError, e2.Error())
				return
			}
			defer dst.Close()
			if _, e3 := io.Copy(dst, src); e3 != nil {
				writeErr(w, http.StatusInternalServerError, e3.Error())
				return
			}
			_ = os.Remove(outPDF)
		}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"%s.pdf\"", strings.TrimSuffix(filepath.Base(abs), filepath.Ext(abs))))
	http.ServeFile(w, r, cachePDF)
}

// Batch download selected files and directories as a ZIP
func handleBatchDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Paths []string `json:"paths"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Paths) == 0 {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\"archive.zip\"")
	zw := zip.NewWriter(w)
	defer zw.Close()
	cl, _ := getUser(r)
	for _, orig := range req.Paths {
		abs, rel, err := resolvePath(r, storageRoot, orig)
		if err != nil {
			continue
		}
		owner := detectOwnerFromRel(filepath.ToSlash(rel))
		if cl.Role != "admin" && owner != "" && owner != cl.Sub {
			continue
		}
		fi, err := os.Stat(abs)
		if err != nil {
			continue
		}
		if fi.IsDir() {
			_ = filepath.WalkDir(abs, func(p string, d os.DirEntry, walkErr error) error {
				if walkErr != nil || d.IsDir() {
					return nil
				}
				relp, _ := filepath.Rel(abs, p)
				zipPath := filepath.ToSlash(filepath.Join(filepath.Base(abs), relp))
				_ = addFileToZip(zw, p, zipPath)
				return nil
			})
		} else {
			_ = addFileToZip(zw, abs, filepath.Base(abs))
		}
	}
}

func addFileToZip(zw *zip.Writer, filePath, zipPath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, _ := f.Stat()
	hdr, err := zip.FileInfoHeader(fi)
	if err != nil {
		return err
	}
	hdr.Name = zipPath
	hdr.Method = zip.Deflate
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, f)
	return err
}

// Batch delete: move multiple files/dirs to trash
func handleBatchDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Paths []string `json:"paths"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Paths) == 0 {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	cl, _ := getUser(r)
	processed := 0
	for _, p := range req.Paths {
		abs, rel, err := resolvePath(r, storageRoot, p)
		if err != nil {
			continue
		}
		owner := detectOwnerFromRel(filepath.ToSlash(rel))
		if cl.Role != "admin" {
			if owner != "" {
				if owner != cl.Sub {
					continue
				}
			} else {
				up := getUploaderForRel(rel)
				if up == "" || up != cl.Sub {
					continue
				}
			}
		}
		if err2 := moveToTrash(abs, rel); err2 == nil {
			processed++
		}
	}
	if processed == 0 {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Batch move: move multiple paths into one target directory
func handleBatchMove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		FromPaths []string `json:"fromPaths"`
		To        string   `json:"to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.FromPaths) == 0 {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	req.To = strings.TrimSpace(req.To) // 允许空字符串表示公共目录根
	absDstDir, relDstDir, err := resolvePath(r, storageRoot, req.To)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	dstFi, err := os.Stat(absDstDir)
	if err != nil || !dstFi.IsDir() {
		writeErr(w, http.StatusBadRequest, "destination not directory")
		return
	}
	cl, _ := getUser(r)
	processed := 0
	for _, p := range req.FromPaths {
		absSrc, relSrc, err := resolvePath(r, storageRoot, p)
		if err != nil {
			continue
		}
		srcFi, err := os.Stat(absSrc)
		if err != nil {
			continue
		}
		owner := detectOwnerFromRel(filepath.ToSlash(relSrc))
		if cl.Role != "admin" {
			if owner != "" {
				if owner != cl.Sub {
					continue
				}
			} else {
				up := getUploaderForRel(relSrc)
				if up == "" || up != cl.Sub {
					continue
				}
			}
		}
		base := filepath.Base(absSrc)
		dstOwner := detectOwnerFromRel(filepath.ToSlash(relDstDir))
		if dstOwner == "" { // 目标公共区，添加拥有者前缀
			prefixUser := owner
			if prefixUser == "" {
				prefixUser = cl.Sub
			}
			noPrefix := base
			samePrefix := fmt.Sprintf("(%s) ", prefixUser)
			if strings.HasPrefix(noPrefix, samePrefix) {
				noPrefix = noPrefix[len(samePrefix):]
			} else if strings.HasPrefix(noPrefix, "(") {
				if i := strings.Index(noPrefix, ") "); i >= 0 {
					noPrefix = noPrefix[i+2:]
				}
			}
			base = fmt.Sprintf("(%s) %s", prefixUser, noPrefix)
		} else { // 目标私有区，去除该私有者前缀
			prefix := fmt.Sprintf("(%s) ", dstOwner)
			if strings.HasPrefix(base, prefix) {
				base = base[len(prefix):]
			}
		}
		newPath := filepath.Join(absDstDir, base)
		// name collision: make unique
		if _, e2 := os.Stat(newPath); e2 == nil {
			newPath = filepath.Join(absDstDir, uniqueFilenameInDir(absDstDir, base))
		}
		if err := os.Rename(absSrc, newPath); err != nil {
			continue
		}
		// migrate indices etc.
		_ = migrateAfterPathChange(filepath.ToSlash(relSrc), filepath.ToSlash(filepath.Join(relDstDir, filepath.Base(newPath))), srcFi.IsDir())
		// record uploader when public
		if detectOwnerFromRel(filepath.ToSlash(relDstDir)) == "" && cl.Sub != "" {
			setUploaderForRel(filepath.ToSlash(filepath.Join(relDstDir, filepath.Base(newPath))), cl.Sub)
		}
		processed++
		appendAudit(cl.Sub, "move", filepath.ToSlash(filepath.Join(relDstDir, filepath.Base(newPath))), func() string {
			if srcFi.IsDir() {
				return "dir"
			}
			return "file"
		}(), sizeOf(srcFi))
	}
	if processed == 0 {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	qpath := r.URL.Query().Get("path")
	abs, rel, err := resolvePath(r, storageRoot, qpath)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// 权限校验：
	// - 私有空间：仅目录所有者或管理员可删除
	// - 公共区：仅上传者或管理员可删除
	cl, _ := getUser(r)
	owner := detectOwnerFromRel(filepath.ToSlash(rel))
	if cl.Role != "admin" {
		if owner != "" {
			if owner != cl.Sub {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
		} else {
			uploader := getUploaderForRel(rel)
			if uploader == "" || uploader != cl.Sub {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
		}
	}
	if err := moveToTrash(abs, rel); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	fiDel, _ := os.Stat(abs)
	var delSize int64
	if fiDel != nil {
		delSize = fiDel.Size()
	}
	appendAudit(cl.Sub, "delete", rel, func() string {
		if fiDel != nil && fiDel.IsDir() {
			return "dir"
		}
		return "file"
	}(), delSize)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Rename a file or directory within the same parent directory
// Request: POST, JSON { path: string, name: string } or query ?path=&name=
func handleRename(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct{ Path, Name string }
	_ = json.NewDecoder(r.Body).Decode(&req)
	if v := r.URL.Query().Get("path"); v != "" {
		req.Path = v
	}
	if v := r.URL.Query().Get("name"); v != "" {
		req.Name = v
	}
	req.Path = strings.TrimSpace(req.Path)
	req.Name = strings.TrimSpace(req.Name)
	if req.Path == "" || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "missing path or name")
		return
	}
	newBase := sanitizeFilename(req.Name)
	if newBase == "." || newBase == ".." {
		writeErr(w, http.StatusBadRequest, "invalid name")
		return
	}
	absSrc, relSrc, err := resolvePath(r, storageRoot, req.Path)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	srcFi, err := os.Stat(absSrc)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	cl, _ := getUser(r)
	owner := detectOwnerFromRel(filepath.ToSlash(relSrc))
	// permission like delete
	if cl.Role != "admin" {
		if owner != "" { // private
			if owner != cl.Sub {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
		} else { // public
			uploader := getUploaderForRel(relSrc)
			if uploader == "" || uploader != cl.Sub {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
		}
	}
	// Public area naming policy for non-admin: enforce (username) prefix
	if owner == "" && cl.Role != "admin" {
		noPrefix := newBase
		if strings.HasPrefix(noPrefix, "(") {
			if i := strings.Index(noPrefix, ") "); i >= 0 {
				noPrefix = noPrefix[i+2:]
			}
		}
		newBase = fmt.Sprintf("(%s) %s", cl.Sub, noPrefix)
	}
	absDir := filepath.Dir(absSrc)
	_, relSrcNorm, _ := resolvePath(r, storageRoot, req.Path)
	relDir := filepath.ToSlash(filepath.Dir(relSrcNorm))
	absDst := filepath.Join(absDir, newBase)
	relDst := filepath.ToSlash(filepath.Join(relDir, newBase))
	if absDst == absSrc {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "name": newBase, "path": relDst})
		return
	}
	// collision handling
	if _, statErr := os.Stat(absDst); statErr == nil {
		if owner != "" { // private: version replacement
			if err := saveVersion(absDst, relDst); err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			_ = os.RemoveAll(absDst)
		} else {
			uploader := getUploaderForRel(relDst)
			if cl.Sub != "" && uploader == cl.Sub {
				if err := saveVersion(absDst, relDst); err != nil {
					writeErr(w, http.StatusInternalServerError, err.Error())
					return
				}
				_ = os.RemoveAll(absDst)
			} else {
				uniq := uniqueFilenameInDir(absDir, newBase)
				if uniq != newBase {
					newBase = uniq
					absDst = filepath.Join(absDir, newBase)
					relDst = filepath.ToSlash(filepath.Join(relDir, newBase))
				}
			}
		}
	}
	if err := os.Rename(absSrc, absDst); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// migrate indices
	_ = migrateAfterPathChange(filepath.ToSlash(relSrcNorm), filepath.ToSlash(relDst), srcFi.IsDir())
	// record uploader for public destination (keeps same uploader)
	if owner == "" && cl.Sub != "" {
		setUploaderForRel(relDst, cl.Sub)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "name": newBase, "path": relDst})
}

// Move a file or directory to another directory
// Request: POST, JSON { from: string, to: string } or query ?from=&to=
func handleMove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct{ From, To string }
	_ = json.NewDecoder(r.Body).Decode(&req)
	if v := r.URL.Query().Get("from"); v != "" {
		req.From = v
	}
	if v := r.URL.Query().Get("to"); v != "" {
		req.To = v
	}
	req.From = strings.TrimSpace(req.From)
	req.To = strings.TrimSpace(req.To) // 允许空字符串表示公共目录根
	if req.From == "" {
		writeErr(w, http.StatusBadRequest, "missing from path")
		return
	}
	absSrc, relSrc, err := resolvePath(r, storageRoot, req.From)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	srcFi, err := os.Stat(absSrc)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	absDstDir, relDstDir, err := resolvePath(r, storageRoot, req.To)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if fi, err2 := os.Stat(absDstDir); err2 == nil && !fi.IsDir() {
		writeErr(w, http.StatusBadRequest, "destination is not a directory")
		return
	}
	// make sure dst dir exists
	if err := os.MkdirAll(absDstDir, 0755); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cl, _ := getUser(r)
	srcOwner := detectOwnerFromRel(filepath.ToSlash(relSrc))
	dstOwner := detectOwnerFromRel(filepath.ToSlash(relDstDir))
	// source permission (like delete)
	if cl.Role != "admin" {
		if srcOwner != "" {
			if srcOwner != cl.Sub {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
		} else {
			uploader := getUploaderForRel(relSrc)
			if uploader == "" || uploader != cl.Sub {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
		}
	}
	// destination constraints: non-admin cannot move into others' private dir
	if cl.Role != "admin" && dstOwner != "" && dstOwner != cl.Sub {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	base := filepath.Base(absSrc)
	if dstOwner == "" { // 目标公共区，添加拥有者前缀
		prefixUser := srcOwner
		if prefixUser == "" {
			prefixUser = cl.Sub
		}
		noPrefix := base
		samePrefix := fmt.Sprintf("(%s) ", prefixUser)
		if strings.HasPrefix(noPrefix, samePrefix) {
			noPrefix = noPrefix[len(samePrefix):]
		} else if strings.HasPrefix(noPrefix, "(") {
			if i := strings.Index(noPrefix, ") "); i >= 0 {
				noPrefix = noPrefix[i+2:]
			}
		}
		base = fmt.Sprintf("(%s) %s", prefixUser, noPrefix)
	} else { // 目标私有区，去除对应前缀
		prefix := fmt.Sprintf("(%s) ", dstOwner)
		if strings.HasPrefix(base, prefix) {
			base = base[len(prefix):]
		}
	}
	absDst := filepath.Join(absDstDir, base)
	relDst := filepath.ToSlash(filepath.Join(relDstDir, base))
	// prevent moving dir into its own subdir
	if srcFi.IsDir() {
		s := filepath.ToSlash(relSrc)
		d := filepath.ToSlash(relDst)
		if d == s || strings.HasPrefix(d, s+"/") {
			writeErr(w, http.StatusBadRequest, "cannot move a directory into itself")
			return
		}
	}
	// collision handling similar to rename
	if _, statErr := os.Stat(absDst); statErr == nil {
		if dstOwner != "" { // private dst: version replace file, or merge dir? simplify: prevent overwrite dir
			if !srcFi.IsDir() {
				if err := saveVersion(absDst, relDst); err != nil {
					writeErr(w, http.StatusInternalServerError, err.Error())
					return
				}
				_ = os.RemoveAll(absDst)
			} else {
				// for dir conflict, choose unique folder name
				uniq := uniqueFilenameInDir(absDstDir, base)
				if uniq != base {
					base = uniq
					absDst = filepath.Join(absDstDir, base)
					relDst = filepath.ToSlash(filepath.Join(relDstDir, base))
				}
			}
		} else { // public dst
			uploader := getUploaderForRel(relDst)
			if cl.Sub != "" && uploader == cl.Sub && !srcFi.IsDir() {
				if err := saveVersion(absDst, relDst); err != nil {
					writeErr(w, http.StatusInternalServerError, err.Error())
					return
				}
				_ = os.RemoveAll(absDst)
			} else {
				uniq := uniqueFilenameInDir(absDstDir, base)
				if uniq != base {
					base = uniq
					absDst = filepath.Join(absDstDir, base)
					relDst = filepath.ToSlash(filepath.Join(relDstDir, base))
				}
			}
		}
	}
	if err := os.Rename(absSrc, absDst); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// migrate indices
	_ = migrateAfterPathChange(filepath.ToSlash(relSrc), filepath.ToSlash(relDst), srcFi.IsDir())
	// record uploader for public destination
	if dstOwner == "" && cl.Sub != "" {
		setUploaderForRel(relDst, cl.Sub)
	}
	appendAudit(cl.Sub, "move", relDst, func() string {
		if srcFi.IsDir() {
			return "dir"
		}
		return "file"
	}(), sizeOf(srcFi))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "path": relDst})
}

// migrateAfterPathChange re-keys FilesIndex, VersionsIndex and SharesIndex when a path changes
func migrateAfterPathChange(oldRel, newRel string, isDir bool) error {
	oldRel = filepath.ToSlash(oldRel)
	newRel = filepath.ToSlash(newRel)
	oldKey := strings.TrimPrefix(oldRel, "/")
	newKey := strings.TrimPrefix(newRel, "/")
	metaMu.Lock()
	defer metaMu.Unlock()
	// FilesIndex
	{
		idx := FilesIndex{}
		_ = loadJSON(filesIndexPath, &idx)
		changed := false
		if isDir {
			for k, v := range idx {
				if k == oldKey || strings.HasPrefix(k, oldKey+"/") {
					rest := strings.TrimPrefix(k, oldKey)
					nk := newKey + rest
					idx[nk] = v
					delete(idx, k)
					changed = true
				}
			}
		} else {
			if v, ok := idx[oldKey]; ok {
				idx[newKey] = v
				delete(idx, oldKey)
				changed = true
			}
			// legacy leading-slash
			legacy := "/" + oldKey
			if v, ok := idx[legacy]; ok {
				idx[newKey] = v
				delete(idx, legacy)
				changed = true
			}
		}
		if changed {
			_ = saveJSON(filesIndexPath, idx)
		}
	}
	// VersionsIndex
	{
		idx := VersionsIndex{}
		_ = loadJSON(versionsIndexPath, &idx)
		changed := false
		if isDir {
			for k, v := range idx {
				if strings.TrimPrefix(k, "/") == oldKey || strings.HasPrefix(strings.TrimPrefix(k, "/"), oldKey+"/") {
					// normalize old
					okey := strings.TrimPrefix(k, "/")
					rest := strings.TrimPrefix(okey, oldKey)
					nk := newKey + rest
					idx[nk] = v
					delete(idx, k)
					changed = true
				}
			}
		} else {
			// handle both normalized and legacy keys
			if v, ok := idx[oldKey]; ok {
				idx[newKey] = v
				delete(idx, oldKey)
				changed = true
			}
			legacy := "/" + oldKey
			if v, ok := idx[legacy]; ok {
				idx[newKey] = v
				delete(idx, legacy)
				changed = true
			}
		}
		if changed {
			_ = saveJSON(versionsIndexPath, idx)
		}
	}
	// SharesIndex
	{
		idx := SharesIndex{}
		_ = loadJSON(sharesIndexPath, &idx)
		// 清理过期或下载次数用尽的外链
		nowTs := time.Now().Unix()
		changed := false
		for tok, v := range idx {
			if (v.ExpireAt > 0 && nowTs > v.ExpireAt) || (v.MaxDownloads > 0 && v.Downloads >= v.MaxDownloads) {
				v.Disabled = true
				idx[tok] = v
				changed = true
			}
		}
		if changed {
			_ = saveJSON(sharesIndexPath, idx)
		}
		changed = false
		for tok, ent := range idx {
			rel := filepath.ToSlash(ent.RelPath)
			if isDir {
				if rel == oldRel || strings.HasPrefix(rel, oldRel+"/") {
					rest := strings.TrimPrefix(rel, oldRel)
					ent.RelPath = filepath.ToSlash(newRel + rest)
					idx[tok] = ent
					changed = true
				}
			} else {
				if rel == oldRel {
					ent.RelPath = newRel
					idx[tok] = ent
					changed = true
				}
			}
		}
		if changed {
			_ = saveJSON(sharesIndexPath, idx)
		}
	}
	return nil
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeShareErr 返回一个友好的 HTML 页面用于分享外链失效等情况
func writeShareErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	page := fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>链接已失效</title><style>body{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,"Noto Sans",sans-serif;background:#f8f9fa;color:#333;}img{width:240px;height:auto;margin-bottom:24px;}h1{font-size:24px;margin-bottom:8px;}p{font-size:16px;margin:0;}</style></head><body><img src="/img/logo.png" alt="Logo"><h1>链接已失效</h1><p>%s</p></body></html>`, msg)
	_, _ = w.Write([]byte(page))
}

// resolvePath wraps safeJoin and additionally maps the virtual prefix "@me" to the
// per-user private directory under .users/<username> using the authenticated user in request.
func resolvePath(r *http.Request, root, reqPath string) (absPath string, relPath string, err error) {
	p := strings.TrimSpace(reqPath)
	mapped := p
	if strings.HasPrefix(p, "@me") {
		cl, ok := getUser(r)
		if !ok || cl.Sub == "" {
			return "", "", fmt.Errorf("unauthorized")
		}
		rest := strings.TrimPrefix(p, "@me")
		rest = strings.TrimPrefix(rest, "/")
		mapped = filepath.ToSlash(filepath.Join(".users", cl.Sub))
		if rest != "" {
			mapped = filepath.ToSlash(filepath.Join(mapped, rest))
		}
	}
	// centralized access control for private space under .users
	norm := filepath.ToSlash(strings.TrimSpace(mapped))
	if strings.HasPrefix(norm, ".users") { // includes .users and .users/...
		cl, ok := getUser(r)
		if !ok {
			return "", "", fmt.Errorf("unauthorized")
		}
		if norm == ".users" || norm == ".users/" {
			// only admin can directly access .users root
			if cl.Role != "admin" {
				return "", "", fmt.Errorf("forbidden")
			}
		} else if strings.HasPrefix(norm, ".users/") {
			rest := strings.TrimPrefix(norm, ".users/")
			owner := rest
			if i := strings.Index(owner, "/"); i >= 0 {
				owner = owner[:i]
			}
			if owner == "" {
				return "", "", fmt.Errorf("invalid path")
			}
			if cl.Role != "admin" && cl.Sub != owner {
				return "", "", fmt.Errorf("forbidden")
			}
		}
	}
	return safeJoin(root, mapped)
}

func safeJoin(root, reqPath string) (absPath string, relPath string, err error) {
	clean := filepath.Clean("/" + strings.TrimSpace(reqPath)) // ensure leading slash for Clean
	// Normalize to forward slashes so leading slash can be trimmed reliably on Windows/Unix
	clean = filepath.ToSlash(clean)
	rel := strings.TrimPrefix(clean, "/")
	if rel == "." { // normalize current directory to root
		rel = ""
	}
	// Ensure OS-specific joining from normalized rel
	abs := filepath.Join(root, filepath.FromSlash(rel))
	abs = filepath.Clean(abs)
	absReal, err := filepath.Abs(abs)
	if err != nil {
		return "", "", err
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", "", err
	}
	if !strings.HasPrefix(strings.ToLower(absReal), strings.ToLower(rootAbs)) {
		return "", "", fmt.Errorf("invalid path")
	}
	return absReal, filepath.ToSlash(rel), nil
}

func sanitizeFilename(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, "/", "_")
	return name
}

// uniqueFilenameInDir returns a non-conflicting filename in the given directory by
// appending " (n)" before the extension when a conflict exists.
func uniqueFilenameInDir(dir, filename string) string {
	// if original not exists, keep it
	p0 := filepath.Join(dir, filename)
	if _, err := os.Stat(p0); os.IsNotExist(err) {
		return filename
	}
	// split ext
	exts := filepath.Ext(filename)
	name := filename[:len(filename)-len(exts)]
	for i := 1; ; i++ {
		cand := fmt.Sprintf("%s (%d)%s", name, i, exts)
		p := filepath.Join(dir, cand)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return cand
		}
	}
}

func sizeOf(info os.FileInfo) int64 {
	if info == nil {
		return 0
	}
	if info.IsDir() {
		return 0
	}
	return info.Size()
}

// ensure multipart import used (avoid unused warnings when refactoring)
func _use(_ *multipart.FileHeader) {}

// === Meta & helpers ===

func ensureMetaPaths() error {
	metaRoot = filepath.Join(storageRoot, ".meta")
	uploadsDir = filepath.Join(storageRoot, ".uploads")
	versionsDir = filepath.Join(storageRoot, ".versions")
	trashDir = filepath.Join(storageRoot, ".trash")
	usersDir = filepath.Join(storageRoot, ".users")
	convertCacheDir = filepath.Join(storageRoot, ".convert-cache")
	usersIndexPath = filepath.Join(metaRoot, "users.json")
	jwtSecretPath = filepath.Join(metaRoot, "jwt.secret")
	sharesIndexPath = filepath.Join(metaRoot, "shares.json")
	versionsIndexPath = filepath.Join(metaRoot, "versions.json")
	trashIndexPath = filepath.Join(metaRoot, "trash.json")
	filesIndexPath = filepath.Join(metaRoot, "files.json")
	for _, p := range []string{metaRoot, uploadsDir, versionsDir, trashDir, usersDir, convertCacheDir} {
		if err := os.MkdirAll(p, 0755); err != nil {
			return err
		}
	}
	// ensure jwt secret
	if err := loadOrInitJWTSecret(); err != nil {
		return err
	}
	// ensure default admin
	if err := ensureDefaultAdmin(); err != nil {
		return err
	}
	return nil
}

func loadOrInitJWTSecret() error {
	if b, err := os.ReadFile(jwtSecretPath); err == nil && len(b) > 0 {
		jwtSecret = bytesTrimSpace(b)
		return nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	if err := os.WriteFile(jwtSecretPath, []byte(hex.EncodeToString(b)), 0600); err != nil {
		return err
	}
	jwtSecret = []byte(hex.EncodeToString(b))
	return nil
}

func bytesTrimSpace(b []byte) []byte { return []byte(strings.TrimSpace(string(b))) }

// Helper: generate random hex token of length 2*n
func randToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Helper: load JSON file into v (ignore if file not exist or empty)
func loadJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	b = bytesTrimSpace(b)
	if len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, v)
}

// Helper: save v as pretty JSON atomically
func saveJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	// Windows 的 os.Rename 在目标文件已存在时会返回错误，导致保存失败。
	if err := os.Rename(tmp, path); err == nil {
		return nil
	} else {
		// 尝试删除原文件后再次重命名
		_ = os.Remove(path)
		if err2 := os.Rename(tmp, path); err2 == nil {
			return nil
		}
		// 仍失败则回退到直接覆盖写入
		if err2 := os.WriteFile(path, data, 0644); err2 != nil {
			return err2
		}
		_ = os.Remove(tmp)
		return nil
	}
}
func ensureDefaultAdmin() error {
	var users UsersIndex
	_ = loadJSON(usersIndexPath, &users)
	if users == nil {
		users = UsersIndex{}
	}
	if u, ok := users["admin"]; ok {
		// 确保管理员信息正确且已审批
		u.Role = "admin"
		u.Approved = true
		users["admin"] = u
		return saveJSON(usersIndexPath, users)
	}
	// Password priority: config > env ADMIN_PASSWORD > auto-generated
	pwd := strings.TrimSpace(appConfig.Admin.Password)
	if pwd == "" {
		pwd = os.Getenv("ADMIN_PASSWORD")
	}
	if pwd == "" {
		// generate a random password and print once
		buf := make([]byte, 6)
		if _, err := rand.Read(buf); err == nil {
			pwd = hex.EncodeToString(buf)
		} else {
			pwd = "admin123"
		}
		log.Printf("[SECURITY] Default admin password generated: %s (please change via config.json and restart)", pwd)
	} else {
		log.Printf("[SECURITY] Using admin password from configuration")
	}
	salt, _ := genSalt(16)
	u := User{Username: "admin", Role: "admin", Salt: salt, PassHash: hashPassword(pwd, salt), Created: time.Now().Unix(), Approved: true}
	users[u.Username] = u
	return saveJSON(usersIndexPath, users)
}

// === Versions ===

type VersionEntry struct {
	TS   int64  `json:"ts"`
	Size int64  `json:"size"`
	Path string `json:"path"` // stored path inside versionsDir
}

type VersionsIndex map[string][]VersionEntry // key: rel path

func saveVersion(absFile, relPath string) error {
	fi, err := os.Stat(absFile)
	if err != nil {
		return err
	}
	id, _ := randToken(8)
	ts := time.Now().Unix()
	verName := fmt.Sprintf("%d_%s", ts, id)
	// 版本目录镜像原路径的子目录
	subDir := filepath.Join(versionsDir, filepath.Dir(relPath))
	if err := os.MkdirAll(subDir, 0755); err != nil {
		return err
	}
	verPath := filepath.Join(subDir, verName)

	// 将当前文件复制到版本目录（保留原文件），而不是移动
	src, err := os.Open(absFile)
	if err != nil {
		return err
	}
	defer src.Close()
	out, err := os.Create(verPath)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, src); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}

	// 构造索引条目
	relativeToVersionsDir := strings.TrimPrefix(verPath, versionsDir)
	relativeToVersionsDir = strings.TrimPrefix(relativeToVersionsDir, string(os.PathSeparator))
	entry := VersionEntry{TS: ts, Size: fi.Size(), Path: filepath.ToSlash(relativeToVersionsDir)}

	metaMu.Lock()
	defer metaMu.Unlock()
	idx := VersionsIndex{}
	_ = loadJSON(versionsIndexPath, &idx)
	key := strings.TrimPrefix(filepath.ToSlash(relPath), "/")
	idx[key] = append(idx[key], entry)
	// 新旧版本按时间倒序存储，便于前端直接展示
	sort.Slice(idx[key], func(i, j int) bool { return idx[key][i].TS > idx[key][j].TS })
	return saveJSON(versionsIndexPath, idx)
}

func handleVersionsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	_, rel, err := resolvePath(r, storageRoot, r.URL.Query().Get("path"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// 权限：私有空间属主或管理员；公共区上传者或管理员
	cl, _ := getUser(r)
	owner := detectOwnerFromRel(filepath.ToSlash(rel))
	if cl.Role != "admin" {
		if owner != "" {
			if owner != cl.Sub {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
		} else {
			uploader := getUploaderForRel(rel)
			if uploader == "" || uploader != cl.Sub {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
		}
	}
	metaMu.Lock()
	defer metaMu.Unlock()
	idx := VersionsIndex{}
	_ = loadJSON(versionsIndexPath, &idx)
	key := strings.TrimPrefix(filepath.ToSlash(rel), "/")
	list := idx[key]
	if len(list) == 0 {
		legacyKey := "/" + key
		if v, ok := idx[legacyKey]; ok && len(v) > 0 {
			list = v
			// migrate to normalized key
			idx[key] = v
			delete(idx, legacyKey)
			_ = saveJSON(versionsIndexPath, idx)
		}
	}
	writeJSON(w, http.StatusOK, list)
}

func handleVersionsRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	abs, rel, err := resolvePath(r, storageRoot, r.URL.Query().Get("path"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// 权限：私有空间属主或管理员；公共区上传者或管理员
	cl, _ := getUser(r)
	owner := detectOwnerFromRel(filepath.ToSlash(rel))
	if cl.Role != "admin" {
		if owner != "" {
			if owner != cl.Sub {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
		} else {
			uploader := getUploaderForRel(rel)
			if uploader == "" || uploader != cl.Sub {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
		}
	}
	tsStr := r.URL.Query().Get("ts")
	if tsStr == "" {
		writeErr(w, http.StatusBadRequest, "missing ts")
		return
	}

	// 仅在读取和可能的迁移时加锁，随后释放锁，避免在调用过程中发生死锁
	metaMu.Lock()
	idx := VersionsIndex{}
	_ = loadJSON(versionsIndexPath, &idx)
	key := strings.TrimPrefix(filepath.ToSlash(rel), "/")
	list := idx[key]
	if len(list) == 0 {
		legacyKey := "/" + key
		if v, ok := idx[legacyKey]; ok && len(v) > 0 {
			list = v
			// migrate to normalized key
			idx[key] = v
			delete(idx, legacyKey)
			_ = saveJSON(versionsIndexPath, idx)
		}
	}
	// 拷贝出快照，防止解锁后底层切片变化
	snapshot := append([]VersionEntry(nil), list...)
	metaMu.Unlock()

	var picked *VersionEntry
	for i := range snapshot {
		if strconv.FormatInt(snapshot[i].TS, 10) == tsStr {
			picked = &snapshot[i]
			break
		}
	}
	if picked == nil {
		writeErr(w, http.StatusNotFound, "version not found")
		return
	}

	verAbs := filepath.Join(versionsDir, filepath.FromSlash(picked.Path))
	if _, err := os.Stat(verAbs); err != nil {
		writeErr(w, http.StatusNotFound, "version file not found")
		return
	}

	// 根据需求：切换版本时不再自动保存当前版本
	// 但为避免数据丢失：若当前文件存在，则先移入回收站，可在“回收站”页面撤销恢复
	if fi, err := os.Stat(abs); err == nil && !fi.IsDir() {
		if err := moveToTrash(abs, rel); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("failed to move current to trash: %v", err))
			return
		}
	}

	// 将选中的历史版本复制回目标位置
	src, err := os.Open(verAbs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer src.Close()

	if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	dst, err := os.Create(abs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	appendAudit(cl.Sub, "version_restore", rel, "file", picked.Size)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// === Trash ===

type TrashEntry struct {
	ID        string `json:"id"`
	RelPath   string `json:"relPath"`
	IsDir     bool   `json:"isDir"`
	Size      int64  `json:"size"`
	DeletedAt int64  `json:"deletedAt"`
	StorePath string `json:"storePath"` // actual path under trashDir
	Owner     string `json:"owner,omitempty"`
}

type TrashIndex map[string]TrashEntry // id -> entry

// New: public content uploader metadata index
// 记录上传者信息，供公共区删除与版本管理权限判定使用
// key 使用去掉前导斜杠的归一化相对路径
// 注意：仅用于公共区（detectOwnerFromRel 为空）
type FileMeta struct {
	Uploader  string `json:"uploader,omitempty"`
	CreatedAt int64  `json:"createdAt,omitempty"`
}

type FilesIndex map[string]FileMeta // key: rel path

func getUploaderForRel(rel string) string {
	key := strings.TrimPrefix(filepath.ToSlash(rel), "/")
	metaMu.Lock()
	defer metaMu.Unlock()
	idx := FilesIndex{}
	_ = loadJSON(filesIndexPath, &idx)
	if fm, ok := idx[key]; ok && fm.Uploader != "" {
		return fm.Uploader
	}
	if fm, ok := idx["/"+key]; ok && fm.Uploader != "" { // migrate legacy leading-slash key
		idx[key] = fm
		delete(idx, "/"+key)
		_ = saveJSON(filesIndexPath, idx)
		return fm.Uploader
	}
	return ""
}

func setUploaderForRel(rel, uploader string) {
	key := strings.TrimPrefix(filepath.ToSlash(rel), "/")
	metaMu.Lock()
	defer metaMu.Unlock()
	idx := FilesIndex{}
	_ = loadJSON(filesIndexPath, &idx)
	fm := idx[key]
	if fm.CreatedAt == 0 {
		fm.CreatedAt = time.Now().Unix()
	}
	fm.Uploader = uploader
	idx[key] = fm
	_ = saveJSON(filesIndexPath, idx)
}

func moveToTrash(abs, rel string) error {
	fi, err := os.Stat(abs)
	if err != nil {
		return err
	}
	id, _ := randToken(8)
	dst := filepath.Join(trashDir, id)
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	if err := os.Rename(abs, dst); err != nil {
		return err
	}
	owner := detectOwnerFromRel(filepath.ToSlash(rel))
	if owner == "" {
		uploader := getUploaderForRel(rel)
		if uploader != "" {
			owner = uploader
		}
	}
	entry := TrashEntry{ID: id, RelPath: filepath.ToSlash(rel), IsDir: fi.IsDir(), Size: sizeOf(fi), DeletedAt: time.Now().Unix(), StorePath: filepath.ToSlash(strings.TrimPrefix(dst, trashDir+string(os.PathSeparator))), Owner: owner}
	metaMu.Lock()
	defer metaMu.Unlock()
	idx := TrashIndex{}
	_ = loadJSON(trashIndexPath, &idx)
	idx[id] = entry
	return saveJSON(trashIndexPath, idx)
}

func handleTrashList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	metaMu.Lock()
	defer metaMu.Unlock()
	idx := TrashIndex{}
	_ = loadJSON(trashIndexPath, &idx)
	cl, _ := getUser(r)
	// return values as slice sorted by DeletedAt desc
	list := make([]TrashEntry, 0, len(idx))
	for _, v := range idx {
		if cl.Role == "admin" {
			list = append(list, v)
			continue
		}
		owner := v.Owner
		if owner == "" {
			owner = detectOwnerFromRel(v.RelPath)
		}
		if owner == cl.Sub {
			list = append(list, v)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].DeletedAt > list[j].DeletedAt })
	writeJSON(w, http.StatusOK, list)
}

func handleTrashRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing id")
		return
	}
	metaMu.Lock()
	defer metaMu.Unlock()
	idx := TrashIndex{}
	_ = loadJSON(trashIndexPath, &idx)
	entry, ok := idx[id]
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	// permission check: non-admin can only restore their own items
	cl, _ := getUser(r)
	owner := entry.Owner
	if owner == "" {
		owner = detectOwnerFromRel(entry.RelPath)
	}
	if cl.Role != "admin" && owner != cl.Sub {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	src := filepath.Join(trashDir, filepath.FromSlash(entry.StorePath))
	dst := filepath.Join(storageRoot, filepath.FromSlash(entry.RelPath))
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := os.Rename(src, dst); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	delete(idx, id)
	// audit
	appendAudit(cl.Sub, "trash_restore", entry.RelPath, func() string {
		if entry.IsDir {
			return "dir"
		}
		return "file"
	}(), entry.Size)
	_ = saveJSON(trashIndexPath, idx)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// 批量还原回收站条目
func handleTrashBatchRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.IDs) == 0 {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}

	metaMu.Lock()
	defer metaMu.Unlock()
	idx := TrashIndex{}
	_ = loadJSON(trashIndexPath, &idx)

	cl, _ := getUser(r)
	var restored int
	for _, id := range req.IDs {
		entry, ok := idx[id]
		if !ok {
			continue
		}
		owner := entry.Owner
		if owner == "" {
			owner = detectOwnerFromRel(entry.RelPath)
		}
		if cl.Role != "admin" && owner != cl.Sub {
			continue // skip unauthorized
		}
		src := filepath.Join(trashDir, filepath.FromSlash(entry.StorePath))
		dst := filepath.Join(storageRoot, filepath.FromSlash(entry.RelPath))
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			continue
		}
		if err := os.Rename(src, dst); err != nil {
			continue
		}
		delete(idx, id)
		// audit
		appendAudit(cl.Sub, "trash_restore", entry.RelPath, func() string {
			if entry.IsDir {
				return "dir"
			}
			return "file"
		}(), entry.Size)
		restored++
	}
	_ = saveJSON(trashIndexPath, idx)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "restored": restored})
}

// 批量彻底删除回收站条目
func handleTrashBatchDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.IDs) == 0 {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}

	metaMu.Lock()
	defer metaMu.Unlock()
	idx := TrashIndex{}
	_ = loadJSON(trashIndexPath, &idx)

	cl, _ := getUser(r)
	var deleted int
	for _, id := range req.IDs {
		entry, ok := idx[id]
		if !ok {
			continue
		}
		owner := entry.Owner
		if owner == "" {
			owner = detectOwnerFromRel(entry.RelPath)
		}
		if cl.Role != "admin" && owner != cl.Sub {
			continue // skip unauthorized
		}
		src := filepath.Join(trashDir, filepath.FromSlash(entry.StorePath))
		_ = os.RemoveAll(src)
		// audit
		appendAudit(cl.Sub, "trash_delete", entry.RelPath, func() string {
			if entry.IsDir {
				return "dir"
			}
			return "file"
		}(), entry.Size)
		delete(idx, id)
		deleted++
	}
	_ = saveJSON(trashIndexPath, idx)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "deleted": deleted})
}

func handleTrashDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing id")
		return
	}
	metaMu.Lock()
	defer metaMu.Unlock()
	idx := TrashIndex{}
	_ = loadJSON(trashIndexPath, &idx)
	entry, ok := idx[id]
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	// permission check
	cl, _ := getUser(r)
	owner := entry.Owner
	if owner == "" {
		owner = detectOwnerFromRel(entry.RelPath)
	}
	if cl.Role != "admin" && owner != cl.Sub {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	src := filepath.Join(trashDir, filepath.FromSlash(entry.StorePath))
	_ = os.RemoveAll(src)
	// audit
	appendAudit(cl.Sub, "trash_delete", entry.RelPath, func() string {
		if entry.IsDir {
			return "dir"
		}
		return "file"
	}(), entry.Size)
	delete(idx, id)
	_ = saveJSON(trashIndexPath, idx)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// 删除指定历史版本
func handleVersionsDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	_, rel, err := resolvePath(r, storageRoot, r.URL.Query().Get("path"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// 权限：私有空间属主或管理员；公共区上传者或管理员
	cl, _ := getUser(r)
	owner := detectOwnerFromRel(filepath.ToSlash(rel))
	if cl.Role != "admin" {
		if owner != "" {
			if owner != cl.Sub {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
		} else {
			uploader := getUploaderForRel(rel)
			if uploader == "" || uploader != cl.Sub {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
		}
	}
	tsStr := r.URL.Query().Get("ts")
	if tsStr == "" {
		writeErr(w, http.StatusBadRequest, "missing ts")
		return
	}

	metaMu.Lock()
	defer metaMu.Unlock()
	idx := VersionsIndex{}
	_ = loadJSON(versionsIndexPath, &idx)
	key := strings.TrimPrefix(filepath.ToSlash(rel), "/")
	list := idx[key]
	if len(list) == 0 {
		// 兼容旧 key
		legacyKey := "/" + key
		if v, ok := idx[legacyKey]; ok && len(v) > 0 {
			key = legacyKey
			list = v
		}
	}

	delIdx := -1
	var delPath string
	for i := range list {
		if strconv.FormatInt(list[i].TS, 10) == tsStr {
			delIdx = i
			delPath = list[i].Path
			break
		}
	}
	if delIdx == -1 {
		writeErr(w, http.StatusNotFound, "version not found")
		return
	}

	// 从索引删除
	list = append(list[:delIdx], list[delIdx+1:]...)
	idx[key] = list
	if err := saveJSON(versionsIndexPath, idx); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	appendAudit(cl.Sub, "version_delete", rel, "file", 0)

	// 删除实际版本文件（若不存在则忽略）
	verAbs := filepath.Join(versionsDir, filepath.FromSlash(delPath))
	if err := os.Remove(verAbs); err != nil && !os.IsNotExist(err) {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// 批量恢复历史版本
func handleVersionsBatchRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Path string   `json:"path"`
		TS   []string `json:"ts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Path == "" || len(req.TS) == 0 {
		writeErr(w, http.StatusBadRequest, "missing path or ts list")
		return
	}
	abs, rel, err := resolvePath(r, storageRoot, req.Path)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	cl, _ := getUser(r)
	owner := detectOwnerFromRel(filepath.ToSlash(rel))
	if cl.Role != "admin" {
		if owner != "" {
			if owner != cl.Sub {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
		} else {
			uploader := getUploaderForRel(rel)
			if uploader == "" || uploader != cl.Sub {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
		}
	}

	metaMu.Lock()
	idx := VersionsIndex{}
	_ = loadJSON(versionsIndexPath, &idx)
	key := strings.TrimPrefix(filepath.ToSlash(rel), "/")
	list := idx[key]
	if len(list) == 0 {
		legacyKey := "/" + key
		if v, ok := idx[legacyKey]; ok && len(v) > 0 {
			list = v
			idx[key] = v
			delete(idx, legacyKey)
			_ = saveJSON(versionsIndexPath, idx)
		}
	}
	snapshot := append([]VersionEntry(nil), list...)
	metaMu.Unlock()

	tsSet := make(map[string]struct{})
	for _, ts := range req.TS {
		tsSet[ts] = struct{}{}
	}

	for tsStr := range tsSet {
		var picked *VersionEntry
		for i := range snapshot {
			if strconv.FormatInt(snapshot[i].TS, 10) == tsStr {
				picked = &snapshot[i]
				break
			}
		}
		if picked == nil {
			continue
		}
		verAbs := filepath.Join(versionsDir, filepath.FromSlash(picked.Path))
		if _, err := os.Stat(verAbs); err != nil {
			continue
		}
		if fi, err := os.Stat(abs); err == nil && !fi.IsDir() {
			_ = moveToTrash(abs, rel)
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
			continue
		}
		src, err := os.Open(verAbs)
		if err != nil {
			continue
		}
		dst, err := os.Create(abs)
		if err != nil {
			src.Close()
			continue
		}
		_, _ = io.Copy(dst, src)
		dst.Close()
		src.Close()
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// 批量删除历史版本
func handleVersionsBatchDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Path string   `json:"path"`
		TS   []string `json:"ts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Path == "" || len(req.TS) == 0 {
		writeErr(w, http.StatusBadRequest, "missing path or ts list")
		return
	}

	// 解析路径并权限校验（复用单删逻辑）
	_, rel, err := resolvePath(r, storageRoot, req.Path)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	cl, _ := getUser(r)
	owner := detectOwnerFromRel(filepath.ToSlash(rel))
	if cl.Role != "admin" {
		if owner != "" {
			if owner != cl.Sub {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
		} else {
			uploader := getUploaderForRel(rel)
			if uploader == "" || uploader != cl.Sub {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
		}
	}

	metaMu.Lock()
	idx := VersionsIndex{}
	_ = loadJSON(versionsIndexPath, &idx)
	key := strings.TrimPrefix(filepath.ToSlash(rel), "/")
	list := idx[key]
	if len(list) == 0 {
		legacyKey := "/" + key
		if v, ok := idx[legacyKey]; ok && len(v) > 0 {
			key = legacyKey
			list = v
		}
	}

	// 标记需删除的索引
	delSet := make(map[string]struct{})
	for _, ts := range req.TS {
		delSet[ts] = struct{}{}
	}

	// 过滤并删除文件
	kept := make([]VersionEntry, 0, len(list))
	for _, v := range list {
		if _, ok := delSet[strconv.FormatInt(v.TS, 10)]; ok {
			verAbs := filepath.Join(versionsDir, filepath.FromSlash(v.Path))
			_ = os.Remove(verAbs) // 忽略不存在错误
		} else {
			kept = append(kept, v)
		}
	}
	idx[key] = kept
	if err := saveJSON(versionsIndexPath, idx); err != nil {
		metaMu.Unlock()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	metaMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// === 搜索 ===

type SearchItem struct {
	Name    string `json:"name"`
	IsDir   bool   `json:"isDir"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"mtime"`
	RelPath string `json:"relPath"`
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cl, _ := getUser(r)
	kw := strings.ToLower(r.URL.Query().Get("kw"))
	typeFilter := r.URL.Query().Get("type") // file | dir | ""
	ownerFilter := r.URL.Query().Get("owner")
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("pageSize"))
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}
	var fromTs, toTs int64
	if fromStr != "" {
		if v, err := strconv.ParseInt(fromStr, 10, 64); err == nil {
			fromTs = v
		}
	}
	if toStr != "" {
		if v, err := strconv.ParseInt(toStr, 10, 64); err == nil {
			toTs = v
		}
	}
	// 指定起始目录（默认根），可通过 path 参数指定当前目录
	baseAbs := storageRoot
	baseRelParam := r.URL.Query().Get("path")
	if baseRelParam != "" && baseRelParam != "/" {
		if abs, relNorm, err := resolvePath(r, storageRoot, baseRelParam); err == nil {
			baseAbs = abs
			// 私有区权限校验
			ownerTmp := detectOwnerFromRel(relNorm)
			if ownerTmp != "" && cl.Role != "admin" && ownerTmp != cl.Sub {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
		}
	}
	// 需要跳过的系统目录
	// 顶层需跳过的系统目录（.users 需要特殊判断，见下）
	skipDirs := map[string]bool{
		".convert-cache": true,
		".meta":          true,
		".trash":         true,
		".uploads":       true,
		".versions":      true,
	}
	var items []SearchItem
	_ = filepath.WalkDir(baseAbs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if path == storageRoot {
			return nil
		}
		rel, _ := filepath.Rel(storageRoot, path)
		rel = filepath.ToSlash(rel)
		// 跳过系统目录：.users 仅在顶层跳过，允许在用户私有目录内搜索
		if parts := strings.Split(rel, "/"); len(parts) > 0 {
			if parts[0] == ".users" {
				// 顶层 .users 目录整体跳过（防止列出所有用户私有目录），
				// 但若当前搜索已位于某个用户私有目录下，则允许继续递归
				if len(parts) == 1 {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
			} else if skipDirs[parts[0]] {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		owner := detectOwnerFromRel(rel)
		// 权限：私有区仅限本人或管理员
		if owner != "" && cl.Role != "admin" && owner != cl.Sub {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if kw != "" && !strings.Contains(strings.ToLower(name), kw) {
			// 关键字不匹配
			if d.IsDir() {
				return nil
			}
			return nil
		}
		if typeFilter == "file" && d.IsDir() {
			return nil
		}
		if typeFilter == "dir" && !d.IsDir() {
			return nil
		}
		if ownerFilter != "" {
			if owner != "" {
				if owner != ownerFilter {
					return nil
				}
			} else { // 公共区：根据上传者过滤
				if up := getUploaderForRel(rel); up != ownerFilter {
					return nil
				}
			}
		}
		info, _ := d.Info()
		if info == nil {
			return nil
		}
		mt := info.ModTime().Unix()
		if fromTs > 0 && mt < fromTs {
			return nil
		}
		if toTs > 0 && mt > toTs {
			return nil
		}
		items = append(items, SearchItem{
			Name:    name,
			IsDir:   d.IsDir(),
			Size:    info.Size(),
			ModTime: mt,
			RelPath: rel,
		})
		return nil
	})
	// 按修改时间倒序
	sort.Slice(items, func(i, j int) bool { return items[i].ModTime > items[j].ModTime })
	total := len(items)
	start := (page - 1) * pageSize
	if start >= total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	resp := map[string]interface{}{
		"total":    total,
		"page":     page,
		"pageSize": pageSize,
		"items":    items[start:end],
	}
	writeJSON(w, http.StatusOK, resp)
}

// === Chunked upload with resume ===

type UploadSession struct {
	ID      string `json:"id"`
	RelPath string `json:"relPath"`
	Size    int64  `json:"size"`
	CTime   int64  `json:"ctime"`
}

func sessionPaths(id string) (metaPath, dataPath string) {
	return filepath.Join(uploadsDir, id+".json"), filepath.Join(uploadsDir, id+".part")
}

func handleUploadInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rel := r.URL.Query().Get("path")
	_, relNorm, err := resolvePath(r, storageRoot, rel)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	szStr := r.URL.Query().Get("size")
	if szStr == "" {
		writeErr(w, http.StatusBadRequest, "missing size")
		return
	}
	size, err := strconv.ParseInt(szStr, 10, 64)
	if err != nil || size < 0 {
		writeErr(w, http.StatusBadRequest, "invalid size")
		return
	}
	id, _ := randToken(12)
	sess := UploadSession{ID: id, RelPath: filepath.ToSlash(relNorm), Size: size, CTime: time.Now().Unix()}
	meta, data := sessionPaths(id)
	if err := saveJSON(meta, &sess); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	f, err := os.Create(data)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	f.Close()
	writeJSON(w, http.StatusOK, map[string]string{"uploadId": id})
}

func handleUploadStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := r.URL.Query().Get("uploadId")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing uploadId")
		return
	}
	meta, data := sessionPaths(id)
	// load session meta
	var sess UploadSession
	if err := loadJSON(meta, &sess); err != nil || sess.ID == "" {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	// permission: only owner or admin can view session status
	cl, _ := getUser(r)
	owner := detectOwnerFromRel(sess.RelPath)
	if cl.Role != "admin" && owner != "" && owner != cl.Sub {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	fi, err := os.Stat(data)
	if err != nil {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"offset": fi.Size()})
}

func handleUploadChunk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := r.URL.Query().Get("uploadId")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing uploadId")
		return
	}

	offStr := r.URL.Query().Get("offset")
	off, err := strconv.ParseInt(offStr, 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid offset")
		return
	}
	meta, data := sessionPaths(id)
	// check exists
	var sess UploadSession
	if err := loadJSON(meta, &sess); err != nil || sess.ID == "" {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	// permission: only owner or admin can upload to this session
	cl, _ := getUser(r)
	owner := detectOwnerFromRel(sess.RelPath)
	if cl.Role != "admin" && owner != "" && owner != cl.Sub {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	f, err := os.OpenFile(data, os.O_RDWR, 0644)
	if err != nil {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	defer f.Close()
	fi, _ := f.Stat()
	if fi.Size() != off {
		writeErr(w, http.StatusConflict, fmt.Sprintf("offset mismatch, want %d", fi.Size()))
		return
	}
	// append
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, err := io.Copy(f, r.Body); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	fi2, _ := f.Stat()
	writeJSON(w, http.StatusOK, map[string]int64{"offset": fi2.Size()})
}

func handleUploadComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := r.URL.Query().Get("uploadId")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing uploadId")
		return
	}
	meta, data := sessionPaths(id)
	var sess UploadSession
	if err := loadJSON(meta, &sess); err != nil || sess.ID == "" {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	// permission: only owner or admin can finalize this session
	cl, _ := getUser(r)
	owner := detectOwnerFromRel(sess.RelPath)
	if cl.Role != "admin" && owner != "" && owner != cl.Sub {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	fi, err := os.Stat(data)
	if err != nil {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	if fi.Size() != sess.Size {
		writeErr(w, http.StatusBadRequest, "size not match")
		return
	}
	// finalize move
	absDst, relDst, err := resolvePath(r, storageRoot, sess.RelPath)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	dir := filepath.Dir(absDst)
	base := filepath.Base(absDst)
	// 公共区：在文件名前添加“(username) ”前缀
	if owner == "" {
		if cl.Sub != "" {
			prefix := fmt.Sprintf("(%s) ", cl.Sub)
			if !strings.HasPrefix(base, prefix) {
				base = prefix + base
			}
		}
	}
	absFinal := filepath.Join(dir, base)
	// 同步相对路径（用于响应与元数据）
	relDir := filepath.ToSlash(filepath.Dir(relDst))
	relFinal := filepath.ToSlash(filepath.Join(relDir, base))
	if err := os.MkdirAll(dir, 0755); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// 已存在：按私有/公共规则处理
	if _, statErr := os.Stat(absFinal); statErr == nil {
		if owner != "" { // 私有：版本替换
			if err := saveVersion(absFinal, relFinal); err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			_ = os.Remove(absFinal)
		} else { // 公共
			uploader := getUploaderForRel(relFinal)
			if cl.Sub != "" && uploader == cl.Sub { // 同用户：版本替换
				if err := saveVersion(absFinal, relFinal); err != nil {
					writeErr(w, http.StatusInternalServerError, err.Error())
					return
				}
				_ = os.Remove(absFinal)
			} else {
				// 不同用户：重命名去冲突
				uniq := uniqueFilenameInDir(dir, base)
				if uniq != base {
					base = uniq
					absFinal = filepath.Join(dir, base)
					relFinal = filepath.ToSlash(filepath.Join(relDir, base))
				}
			}
		}
	}
	if err := os.Rename(data, absFinal); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = os.Remove(meta)
	// 记录上传者（公共区权限）
	if cl.Sub != "" {
		setUploaderForRel(relFinal, cl.Sub)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "name": base, "path": relFinal})
}

// === Shares ===

type ShareEntry struct {
	Token        string `json:"token"`
	RelPath      string `json:"relPath"`
	ExpireAt     int64  `json:"expireAt"`
	Password     string `json:"password,omitempty"`
	CreatedAt    int64  `json:"createdAt"`
	CreatedBy    string `json:"createdBy,omitempty"`
	MaxDownloads int    `json:"maxDownloads,omitempty"`
	Downloads    int    `json:"downloads"`
	Disabled     bool   `json:"disabled,omitempty"`
}

type SharesIndex map[string]ShareEntry // token -> entry

func handleShareCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Path         string `json:"path"`
		ExpireHours  int    `json:"expireHours"`
		Password     string `json:"password"`
		MaxDownloads int    `json:"maxDownloads"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	abs, rel, err := resolvePath(r, storageRoot, req.Path)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	fi, err := os.Stat(abs)
	if err != nil || fi.IsDir() {
		writeErr(w, http.StatusBadRequest, "path must be a file")
		return
	}
	if req.ExpireHours <= 0 {
		req.ExpireHours = 24
	}
	tok, _ := randToken(16)
	cl, _ := getUser(r)
	entry := ShareEntry{Token: tok, RelPath: filepath.ToSlash(rel), ExpireAt: time.Now().Add(time.Duration(req.ExpireHours) * time.Hour).Unix(), Password: req.Password, CreatedAt: time.Now().Unix(), CreatedBy: cl.Sub, MaxDownloads: req.MaxDownloads}
	metaMu.Lock()
	defer metaMu.Unlock()
	idx := SharesIndex{}
	_ = loadJSON(sharesIndexPath, &idx)
	idx[tok] = entry
	if err := saveJSON(sharesIndexPath, idx); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	appendAudit(cl.Sub, "share_create", filepath.ToSlash(rel), "file", fi.Size())
	writeJSON(w, http.StatusOK, map[string]string{"token": tok, "url": "/s/" + tok})
}

func handleShareList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	metaMu.Lock()
	defer metaMu.Unlock()
	idx := SharesIndex{}
	_ = loadJSON(sharesIndexPath, &idx)

	// 在返回列表前先同步检查过期/超限，若需要则标记失效并持久化
	nowTs := time.Now().Unix()
	changed := false
	for k, v := range idx {
		if v.Disabled {
			continue
		}
		if (v.ExpireAt > 0 && nowTs > v.ExpireAt) || (v.MaxDownloads > 0 && v.Downloads >= v.MaxDownloads) {
			v.Disabled = true
			idx[k] = v
			changed = true
		}
	}
	if changed {
		_ = saveJSON(sharesIndexPath, idx)
	}

	cl, _ := getUser(r)
	// to slice with filtering for non-admin users (by CreatedBy)
	list := make([]ShareEntry, 0, len(idx))
	for _, v := range idx {
		if cl.Role == "admin" {
			list = append(list, v)
			continue
		}
		if v.CreatedBy == cl.Sub {
			list = append(list, v)
		}
	}
	writeJSON(w, http.StatusOK, list)
}

func handleShareRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		writeErr(w, http.StatusBadRequest, "missing token")
		return
	}
	metaMu.Lock()
	defer metaMu.Unlock()
	idx := SharesIndex{}
	_ = loadJSON(sharesIndexPath, &idx)
	entry, ok := idx[token]
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	// permission: only creator or admin can revoke
	cl, _ := getUser(r)
	if cl.Role != "admin" && entry.CreatedBy != cl.Sub {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	entry.Disabled = true
	idx[token] = entry
	_ = saveJSON(sharesIndexPath, idx)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleShareDownload(w http.ResponseWriter, r *http.Request) {
	// path: /s/{token}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/s/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeErr(w, http.StatusBadRequest, "missing token")
		return
	}
	token := parts[0]
	pwd := r.URL.Query().Get("pwd")
	metaMu.Lock()
	defer metaMu.Unlock()
	idx := SharesIndex{}
	_ = loadJSON(sharesIndexPath, &idx)
	entry, ok := idx[token]
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if entry.Disabled {
		writeShareErr(w, http.StatusGone, "外链已失效")
		return
	}
	if entry.ExpireAt > 0 && time.Now().Unix() > entry.ExpireAt {
		entry.Disabled = true
		idx[token] = entry
		_ = saveJSON(sharesIndexPath, idx)
		writeShareErr(w, http.StatusGone, "外链已过期")
		return
	}
	if entry.MaxDownloads > 0 && entry.Downloads >= entry.MaxDownloads {
		entry.Disabled = true
		idx[token] = entry
		_ = saveJSON(sharesIndexPath, idx)
		writeShareErr(w, http.StatusGone, "下载次数已用完")
		return
	}
	if entry.Password != "" && entry.Password != pwd {
		writeShareErr(w, http.StatusForbidden, "需要密码或密码错误")
		return
	}
	abs := filepath.Join(storageRoot, filepath.FromSlash(entry.RelPath))
	fi, err := os.Stat(abs)
	if err != nil || fi.IsDir() {
		writeErr(w, http.StatusNotFound, "file not found")
		return
	}
	// 计算本次下载后次数
	if entry.MaxDownloads > 0 && entry.Downloads+1 > entry.MaxDownloads {
		// 已超出上限：标记禁用并拒绝下载
		entry.Disabled = true
		idx[token] = entry
		_ = saveJSON(sharesIndexPath, idx)
		writeErr(w, http.StatusGone, "download limit exceeded")
		return
	}

	// 递增并保存
	entry.Downloads++
	if entry.MaxDownloads > 0 && entry.Downloads >= entry.MaxDownloads {
		entry.Disabled = true
	}
	idx[token] = entry
	_ = saveJSON(sharesIndexPath, idx)

	// 禁止浏览器缓存，确保每次下载都会触发后端计数
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(abs)))
	http.ServeFile(w, r, abs)
}

func detectOwnerFromRel(rel string) string {
	rel = filepath.ToSlash(rel)
	if strings.HasPrefix(rel, ".users/") {
		rest := strings.TrimPrefix(rel, ".users/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) > 0 && parts[0] != "" {
			return parts[0]
		}
	}
	return ""
}
