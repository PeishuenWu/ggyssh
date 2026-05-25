package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	_ "modernc.org/sqlite"
)

const (
	webSessionCookie  = "ggyssh_web_session"
	adminGateCookie   = "ggyssh_admin_gate"
	sessionCookieDays = 1
)

type WebAuthnConfig struct {
	Enabled       bool     `json:"enabled,omitempty"`
	RPID          string   `json:"rp_id,omitempty"`
	RPDisplayName string   `json:"rp_display_name,omitempty"`
	Origins       []string `json:"origins,omitempty"`
	Origin        string   `json:"origin,omitempty"`
	AdminUser     string   `json:"admin_user,omitempty"`
	DBPath        string   `json:"db_path,omitempty"`
	SessionHours  int      `json:"session_hours,omitempty"`
}

type AdminConfig struct {
	Enabled            bool   `json:"enabled,omitempty"`
	Path               string `json:"path,omitempty"`
	TokenHash          string `json:"token_hash,omitempty"`
	BootstrapTokenHash string `json:"bootstrap_token_hash,omitempty"`
	TokenRequired      bool   `json:"token_required,omitempty"`
}

type authState struct {
	db                *sql.DB
	web               *webauthn.WebAuthn
	challengeSessions map[string]webauthn.SessionData
	challengeMutex    sync.Mutex
}

type webUser struct {
	ID          string
	Name        string
	DisplayName string
	Role        string
	Credentials []webauthn.Credential
}

func (u *webUser) WebAuthnID() []byte {
	return []byte(u.ID)
}

func (u *webUser) WebAuthnName() string {
	return u.Name
}

func (u *webUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *webUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

var auth *authState

func initAuth() {
	if !globalConfig.WebAuthn.Enabled {
		return
	}

	cfg := globalConfig.WebAuthn
	if cfg.AdminUser == "" {
		cfg.AdminUser = "admin"
	}
	if cfg.DBPath == "" {
		cfg.DBPath = "ggyssh.sqlite"
	}
	if cfg.RPDisplayName == "" {
		cfg.RPDisplayName = "GgySSH"
	}
	if cfg.RPID == "" {
		logFatal("webauthn.rp_id is required when webauthn is enabled")
	}
	origins := cfg.Origins
	if cfg.Origin != "" {
		origins = append(origins, cfg.Origin)
	}
	if len(origins) == 0 {
		logFatal("webauthn.origin or webauthn.origins is required when webauthn is enabled")
	}

	db, err := sql.Open("sqlite", cfg.DBPath)
	if err != nil {
		logFatal("open sqlite: %v", err)
	}
	if err := migrateAuthDB(db); err != nil {
		logFatal("migrate sqlite: %v", err)
	}
	if err := ensureUser(db, cfg.AdminUser, "Admin", "admin"); err != nil {
		logFatal("ensure admin user: %v", err)
	}

	wan, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     origins,
	})
	if err != nil {
		logFatal("init webauthn: %v", err)
	}

	auth = &authState{
		db:                db,
		web:               wan,
		challengeSessions: make(map[string]webauthn.SessionData),
	}
}

func logFatal(format string, args ...any) {
	log.Fatalf(format, args...)
}

func migrateAuthDB(db *sql.DB) error {
	stmts := []string{
		`create table if not exists users (
			id text primary key,
			username text not null unique,
			display_name text not null,
			role text not null,
			created_at text not null
		)`,
		`create table if not exists webauthn_credentials (
			id integer primary key autoincrement,
			user_id text not null,
			credential_id text not null unique,
			name text not null,
			credential_json text not null,
			active integer not null default 1,
			created_at text not null,
			last_used_at text,
			foreign key(user_id) references users(id)
		)`,
		`create table if not exists web_sessions (
			id integer primary key autoincrement,
			user_id text not null,
			token_hash text not null unique,
			created_at text not null,
			expires_at text not null,
			last_seen_at text not null,
			ip text,
			user_agent text,
			revoked_at text,
			foreign key(user_id) references users(id)
		)`,
		`create table if not exists admin_gates (
			id integer primary key autoincrement,
			token_hash text not null unique,
			created_at text not null,
			expires_at text not null,
			ip text,
			user_agent text
		)`,
		`create table if not exists audit_logs (
			id integer primary key autoincrement,
			user_id text,
			event_type text not null,
			success integer not null,
			ip text,
			user_agent text,
			detail text,
			created_at text not null
		)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func ensureUser(db *sql.DB, username, displayName, role string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(
		`insert into users(id, username, display_name, role, created_at)
		 values(?, ?, ?, ?, ?)
		 on conflict(id) do update set username=excluded.username, display_name=excluded.display_name, role=excluded.role`,
		username, username, displayName, role, now,
	)
	return err
}

func loadWebUser(userID string) (*webUser, error) {
	if auth == nil {
		return nil, errors.New("webauthn disabled")
	}
	row := auth.db.QueryRow(`select id, username, display_name, role from users where id = ?`, userID)
	user := &webUser{}
	if err := row.Scan(&user.ID, &user.Name, &user.DisplayName, &user.Role); err != nil {
		return nil, err
	}
	rows, err := auth.db.Query(`select credential_json from webauthn_credentials where user_id = ? and active = 1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var cred webauthn.Credential
		if err := json.Unmarshal([]byte(raw), &cred); err != nil {
			return nil, err
		}
		user.Credentials = append(user.Credentials, cred)
	}
	return user, rows.Err()
}

func saveCredential(userID, name string, cred *webauthn.Credential) error {
	raw, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	if name == "" {
		name = "Security Key"
	}
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = auth.db.Exec(
		`insert into webauthn_credentials(user_id, credential_id, name, credential_json, active, created_at)
		 values(?, ?, ?, ?, 1, ?)
		 on conflict(credential_id) do update set name=excluded.name, credential_json=excluded.credential_json, active=1`,
		userID, credID, name, string(raw), now,
	)
	return err
}

func updateCredentialUse(userID string, cred *webauthn.Credential) error {
	raw, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = auth.db.Exec(
		`update webauthn_credentials set credential_json = ?, last_used_at = ? where user_id = ? and credential_id = ?`,
		string(raw), now, userID, credID,
	)
	return err
}

func credentialCount() int {
	if auth == nil {
		return 0
	}
	var n int
	_ = auth.db.QueryRow(`select count(*) from webauthn_credentials where active = 1`).Scan(&n)
	return n
}

func bootstrapAvailable() bool {
	return globalConfig.WebAuthn.Enabled && credentialCount() == 0
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if i := strings.IndexByte(fwd, ','); i >= 0 {
			return strings.TrimSpace(fwd[:i])
		}
		return strings.TrimSpace(fwd)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func audit(r *http.Request, userID, eventType string, success bool, detail string) {
	if auth == nil {
		return
	}
	ok := 0
	if success {
		ok = 1
	}
	_, _ = auth.db.Exec(
		`insert into audit_logs(user_id, event_type, success, ip, user_agent, detail, created_at)
		 values(?, ?, ?, ?, ?, ?, ?)`,
		userID, eventType, ok, clientIP(r), r.UserAgent(), detail, time.Now().UTC().Format(time.RFC3339),
	)
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func verifyConfiguredToken(token, configuredHash string) bool {
	if token == "" || configuredHash == "" {
		return false
	}
	expected := strings.TrimSpace(configuredHash)
	if strings.HasPrefix(expected, "sha256:") {
		expected = strings.TrimPrefix(expected, "sha256:")
	}
	actual := tokenHash(token)
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

func cookieSecure(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func setCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   cookieSecure(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func currentWebUser(r *http.Request) (*webUser, bool) {
	if auth == nil {
		return nil, false
	}
	cookie, err := r.Cookie(webSessionCookie)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	hash := tokenHash(cookie.Value)
	now := time.Now().UTC().Format(time.RFC3339)
	var userID string
	err = auth.db.QueryRow(
		`select user_id from web_sessions where token_hash = ? and revoked_at is null and expires_at > ?`,
		hash, now,
	).Scan(&userID)
	if err != nil {
		return nil, false
	}
	_, _ = auth.db.Exec(`update web_sessions set last_seen_at = ? where token_hash = ?`, now, hash)
	user, err := loadWebUser(userID)
	return user, err == nil
}

func createWebSession(w http.ResponseWriter, r *http.Request, userID string) error {
	token, err := randomToken()
	if err != nil {
		return err
	}
	hours := globalConfig.WebAuthn.SessionHours
	if hours <= 0 {
		hours = 24
	}
	now := time.Now().UTC()
	expires := now.Add(time.Duration(hours) * time.Hour)
	_, err = auth.db.Exec(
		`insert into web_sessions(user_id, token_hash, created_at, expires_at, last_seen_at, ip, user_agent)
		 values(?, ?, ?, ?, ?, ?, ?)`,
		userID, tokenHash(token), now.Format(time.RFC3339), expires.Format(time.RFC3339), now.Format(time.RFC3339), clientIP(r), r.UserAgent(),
	)
	if err != nil {
		return err
	}
	setCookie(w, r, webSessionCookie, token, hours*3600)
	return nil
}

func requireWebAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !globalConfig.WebAuthn.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := currentWebUser(r); !ok {
			http.Error(w, "WebAuthn authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func adminGateOK(r *http.Request) bool {
	if !globalConfig.Admin.TokenRequired {
		return true
	}
	cookie, err := r.Cookie(adminGateCookie)
	if err != nil || cookie.Value == "" || auth == nil {
		return false
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var n int
	err = auth.db.QueryRow(`select count(*) from admin_gates where token_hash = ? and expires_at > ?`, tokenHash(cookie.Value), now).Scan(&n)
	return err == nil && n > 0
}

func requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !globalConfig.WebAuthn.Enabled || !globalConfig.Admin.Enabled {
			http.NotFound(w, r)
			return
		}
		if !adminGateOK(r) {
			http.Error(w, "admin token required", http.StatusUnauthorized)
			return
		}
		user, ok := currentWebUser(r)
		if !ok || user.Role != "admin" {
			http.Error(w, "admin WebAuthn session required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleAdminGate(w http.ResponseWriter, r *http.Request) {
	if !globalConfig.Admin.Enabled {
		http.NotFound(w, r)
		return
	}
	token := r.URL.Query().Get("token")
	hash := globalConfig.Admin.TokenHash
	if bootstrapAvailable() && globalConfig.Admin.BootstrapTokenHash != "" {
		hash = globalConfig.Admin.BootstrapTokenHash
	}
	if globalConfig.Admin.TokenRequired && !adminGateOK(r) {
		if !verifyConfiguredToken(token, hash) {
			audit(r, "", "admin_token_failed", false, "")
			http.Error(w, "invalid admin token", http.StatusUnauthorized)
			return
		}
		raw, err := randomToken()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		now := time.Now().UTC()
		_, _ = auth.db.Exec(
			`insert into admin_gates(token_hash, created_at, expires_at, ip, user_agent) values(?, ?, ?, ?, ?)`,
			tokenHash(raw), now.Format(time.RFC3339), now.Add(10*time.Minute).Format(time.RFC3339), clientIP(r), r.UserAgent(),
		)
		setCookie(w, r, adminGateCookie, raw, 600)
		audit(r, "", "admin_token_success", true, "")
		adminPath := globalConfig.Admin.Path
		if adminPath == "" {
			adminPath = "/admin"
		}
		http.Redirect(w, r, strings.TrimRight(adminPath, "/")+"/", http.StatusFound)
		return
	}
	http.ServeFile(w, r, "static/admin.html")
}

func handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"enabled":             globalConfig.WebAuthn.Enabled,
		"bootstrap_available": bootstrapAvailable(),
		"sso_enabled":         globalConfig.SSO.Enabled,
	}
	if user, ok := currentWebUser(r); ok {
		resp["authenticated"] = true
		resp["user"] = user.Name
		resp["role"] = user.Role
		resp["admin_gate"] = adminGateOK(r)
	} else {
		resp["authenticated"] = false
		resp["admin_gate"] = adminGateOK(r)
	}
	writeJSON(w, resp)
}

func handleAuthLoginBegin(w http.ResponseWriter, r *http.Request) {
	if auth == nil {
		http.NotFound(w, r)
		return
	}
	user, err := loadWebUser(globalConfig.WebAuthn.AdminUser)
	if err != nil || len(user.Credentials) == 0 {
		audit(r, globalConfig.WebAuthn.AdminUser, "webauthn_login_begin", false, "no credentials")
		http.Error(w, "no registered security key", http.StatusBadRequest)
		return
	}
	options, session, err := auth.web.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		audit(r, user.ID, "webauthn_login_begin", false, err.Error())
		http.Error(w, err.Error(), 400)
		return
	}
	id, _ := randomToken()
	auth.challengeMutex.Lock()
	auth.challengeSessions[id] = *session
	auth.challengeMutex.Unlock()
	writeJSON(w, map[string]any{"session_id": id, "options": options})
}

func handleAuthLoginFinish(w http.ResponseWriter, r *http.Request) {
	if auth == nil {
		http.NotFound(w, r)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
	}
	body, _ := ioReadAll(r)
	_ = json.Unmarshal(body, &req)
	auth.challengeMutex.Lock()
	session, ok := auth.challengeSessions[req.SessionID]
	if !ok {
		auth.challengeMutex.Unlock()
		http.Error(w, "invalid login session", 400)
		return
	}
	delete(auth.challengeSessions, req.SessionID)
	auth.challengeMutex.Unlock()
	user, err := loadWebUser(globalConfig.WebAuthn.AdminUser)
	if err != nil {
		http.Error(w, "user not found", 400)
		return
	}
	r.Body = newReadCloser(body)
	cred, err := auth.web.FinishLogin(user, session, r)
	if err != nil {
		audit(r, user.ID, "webauthn_login_failed", false, err.Error())
		http.Error(w, err.Error(), 401)
		return
	}
	_ = updateCredentialUse(user.ID, cred)
	if err := createWebSession(w, r, user.ID); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	audit(r, user.ID, "webauthn_login_success", true, "")
	writeJSON(w, map[string]any{"ok": true})
}

func canRegisterKey(r *http.Request) bool {
	if bootstrapAvailable() && adminGateOK(r) {
		return true
	}
	user, ok := currentWebUser(r)
	return ok && user.Role == "admin" && adminGateOK(r)
}

func handleAuthRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if auth == nil {
		http.NotFound(w, r)
		return
	}
	if !canRegisterKey(r) {
		http.Error(w, "admin authorization required", http.StatusForbidden)
		return
	}
	user, err := loadWebUser(globalConfig.WebAuthn.AdminUser)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	options, session, err := auth.web.BeginRegistration(user, webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
		UserVerification: protocol.VerificationPreferred,
	}))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	id, _ := randomToken()
	auth.challengeMutex.Lock()
	auth.challengeSessions[id] = *session
	auth.challengeMutex.Unlock()
	writeJSON(w, map[string]any{"session_id": id, "options": options})
}

func handleAuthRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if auth == nil {
		http.NotFound(w, r)
		return
	}
	if !canRegisterKey(r) {
		http.Error(w, "admin authorization required", http.StatusForbidden)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
		Name      string `json:"name"`
	}
	body, _ := ioReadAll(r)
	_ = json.Unmarshal(body, &req)
	auth.challengeMutex.Lock()
	session, ok := auth.challengeSessions[req.SessionID]
	if !ok {
		auth.challengeMutex.Unlock()
		http.Error(w, "invalid registration session", 400)
		return
	}
	delete(auth.challengeSessions, req.SessionID)
	auth.challengeMutex.Unlock()
	user, err := loadWebUser(globalConfig.WebAuthn.AdminUser)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	r.Body = newReadCloser(body)
	cred, err := auth.web.FinishRegistration(user, session, r)
	if err != nil {
		audit(r, user.ID, "webauthn_register_failed", false, err.Error())
		http.Error(w, err.Error(), 400)
		return
	}
	if err := saveCredential(user.ID, req.Name, cred); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	audit(r, user.ID, "webauthn_register_success", true, req.Name)
	if _, ok := currentWebUser(r); !ok {
		_ = createWebSession(w, r, user.ID)
	}
	writeJSON(w, map[string]any{"ok": true})
}

func handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(webSessionCookie); err == nil {
		_, _ = auth.db.Exec(`update web_sessions set revoked_at = ? where token_hash = ?`, time.Now().UTC().Format(time.RFC3339), tokenHash(cookie.Value))
	}
	setCookie(w, r, webSessionCookie, "", -1)
	audit(r, "", "webauthn_logout", true, "")
	writeJSON(w, map[string]any{"ok": true})
}

func handleAdminKeys(w http.ResponseWriter, r *http.Request) {
	rows, err := auth.db.Query(`select id, name, credential_id, active, created_at, last_used_at from webauthn_credentials order by created_at desc`)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	var items []map[string]any
	for rows.Next() {
		var id int
		var name, credID, created string
		var last sql.NullString
		var active int
		if err := rows.Scan(&id, &name, &credID, &active, &created, &last); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		items = append(items, map[string]any{
			"id":            id,
			"name":          name,
			"credential_id": credID,
			"active":        active == 1,
			"created_at":    created,
			"last_used_at":  last.String,
		})
	}
	writeJSON(w, items)
}

func handleAdminKeyAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     int    `json:"id"`
		Name   string `json:"name"`
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	switch req.Action {
	case "rename":
		_, _ = auth.db.Exec(`update webauthn_credentials set name = ? where id = ?`, req.Name, req.ID)
		audit(r, globalConfig.WebAuthn.AdminUser, "admin_key_rename", true, fmt.Sprintf("%d", req.ID))
	case "disable":
		_, _ = auth.db.Exec(`update webauthn_credentials set active = 0 where id = ?`, req.ID)
		audit(r, globalConfig.WebAuthn.AdminUser, "admin_key_disable", true, fmt.Sprintf("%d", req.ID))
	case "enable":
		_, _ = auth.db.Exec(`update webauthn_credentials set active = 1 where id = ?`, req.ID)
		audit(r, globalConfig.WebAuthn.AdminUser, "admin_key_enable", true, fmt.Sprintf("%d", req.ID))
	default:
		http.Error(w, "unknown action", 400)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	rows, err := auth.db.Query(
		`select id, user_id, event_type, success, ip, user_agent, detail, created_at
		 from audit_logs order by id desc limit 200`,
	)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	var items []map[string]any
	for rows.Next() {
		var id, success int
		var userID, eventType, ip, ua, detail, created sql.NullString
		if err := rows.Scan(&id, &userID, &eventType, &success, &ip, &ua, &detail, &created); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		items = append(items, map[string]any{
			"id":         id,
			"user_id":    userID.String,
			"event_type": eventType.String,
			"success":    success == 1,
			"ip":         ip.String,
			"user_agent": ua.String,
			"detail":     detail.String,
			"created_at": created.String,
		})
	}
	writeJSON(w, items)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func ioReadAll(r *http.Request) ([]byte, error) {
	return io.ReadAll(r.Body)
}

func newReadCloser(b []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(b))
}
