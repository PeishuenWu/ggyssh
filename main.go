package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type HostConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type Config struct {
	ServerPort           string         `json:"server_port"`
	Hosts                []HostConfig   `json:"hosts"`
	BasePath             string         `json:"base_path,omitempty"`
	DisablePasswordLogin bool           `json:"disable_password_login,omitempty"`
	WebAuthn             WebAuthnConfig `json:"webauthn,omitempty"`
	Admin                AdminConfig    `json:"admin,omitempty"`
}

var globalConfig Config

// Session management
type Session struct {
	ID         string
	SSHClient  *ssh.Client
	SFTPClient *sftp.Client
	Username   string
	HomeRoot   string
	LastAccess time.Time
}

var (
	sessionStore = make(map[string]*Session)
	sessionMutex sync.RWMutex
)

func getSSHConfig(user, authType, pass, key string) (*ssh.ClientConfig, error) {
	var auth []ssh.AuthMethod
	if authType == "key" {
		if key == "" {
			return nil, fmt.Errorf("private key is empty")
		}

		var signer ssh.Signer
		var err error

		signer, err = ssh.ParsePrivateKey([]byte(key))
		if err != nil {
			log.Printf("Non-encrypted key parse failed: %v. Attempting with passphrase.", err)
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(key), []byte(pass))
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key: %v", err)
			}
		}

		auth = append(auth, ssh.PublicKeys(signer))
	} else {
		if globalConfig.DisablePasswordLogin {
			return nil, fmt.Errorf("password login is disabled by administrator")
		}
		auth = append(auth, ssh.Password(pass))
	}

	return &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, nil
}

func loadConfig() {
	file, err := os.Open("config.json")
	if err != nil {
		log.Println("Config file not found, using defaults")
		globalConfig = Config{
			ServerPort: "8080",
			Hosts: []HostConfig{
				{Host: "127.0.0.1", Port: 22},
			},
		}
		return
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&globalConfig)
	if err != nil {
		log.Fatal("Error decoding config:", err)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

func normalizePathPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "/" {
		return ""
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	prefix = strings.TrimRight(prefix, "/")
	if prefix == "/" {
		return ""
	}
	return prefix
}

func stripPrefix(p, prefix string) (string, bool) {
	if prefix == "" {
		return p, false
	}
	if p == prefix {
		return "/", true
	}
	if strings.HasPrefix(p, prefix+"/") {
		return strings.TrimPrefix(p, prefix), true
	}
	return p, false
}

func rewriteBySuffix(p string) string {
	if p == "" {
		return "/"
	}

	known := []string{
		"/sftp/raw",
		"/sftp/action",
		"/sftp/list",
		"/upload",
		"/ws",
		"/login",
		"/auth/status",
		"/auth/login/begin",
		"/auth/login/finish",
		"/auth/register/begin",
		"/auth/register/finish",
		"/auth/logout",
		"/admin/api/keys",
		"/admin/api/key",
		"/admin/api/audit",
		"/admin",
		"/config",
	}

	for _, k := range known {
		if strings.HasSuffix(p, k) || strings.HasSuffix(p, k+"/") {
			return k
		}
	}

	if strings.HasSuffix(p, "/index.html") {
		return "/index.html"
	}
	if strings.HasSuffix(p, "/") {
		return "/"
	}

	if !strings.Contains(path.Base(p), ".") {
		return "/"
	}

	return p
}

func pathRewriteMiddleware(next http.Handler) http.Handler {
	basePrefix := normalizePathPrefix(globalConfig.BasePath)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origPath := r.URL.Path
		newPath := origPath

		if p, ok := stripPrefix(newPath, basePrefix); ok {
			newPath = p
		}

		if fwd := r.Header.Get("X-Forwarded-Prefix"); newPath == origPath && fwd != "" {
			if i := strings.IndexByte(fwd, ','); i >= 0 {
				fwd = fwd[:i]
			}
			if p, ok := stripPrefix(newPath, normalizePathPrefix(fwd)); ok {
				newPath = p
			}
		}

		if newPath == origPath {
			newPath = rewriteBySuffix(origPath)
		}

		if newPath == origPath {
			next.ServeHTTP(w, r)
			return
		}

		r2 := r.Clone(r.Context())
		u := *r.URL
		u.Path = newPath
		r2.URL = &u
		next.ServeHTTP(w, r2)
	})
}

type FileInfo struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	IsDir bool   `json:"is_dir"`
	Mode  string `json:"mode"`
	Time  string `json:"time"`
}

type wsWriter struct {
	conn *websocket.Conn
	mu   *sync.Mutex
}

func (w *wsWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	err := w.conn.WriteMessage(websocket.BinaryMessage, p)
	return len(p), err
}

type WSControlMessage struct {
	Type string `json:"type"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

func readWebSocketInput(conn *websocket.Conn, stdin io.Writer, session *ssh.Session) {
	for {
		msgType, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}

		if msgType == websocket.TextMessage {
			var ctrl WSControlMessage
			if err := json.Unmarshal(msg, &ctrl); err == nil && ctrl.Type == "resize" && ctrl.Cols > 0 && ctrl.Rows > 0 {
				_ = session.WindowChange(ctrl.Rows, ctrl.Cols)
				continue
			}
		}

		if _, err := stdin.Write(msg); err != nil {
			return
		}
	}
}

func userHomeRoot(username string) string {
	u := strings.TrimSpace(username)
	if u == "" || u == "root" {
		return "/"
	}
	return "/home/" + u
}

func normalizePathWithinHome(session *Session, requestedPath string) (string, error) {
	if session == nil {
		return "", fmt.Errorf("session expired")
	}
	home := path.Clean(session.HomeRoot)
	p := strings.TrimSpace(requestedPath)
	if p == "" || p == "." {
		return home, nil
	}
	if !strings.HasPrefix(p, "/") {
		p = path.Join(home, p)
	}
	p = path.Clean(p)
	if p == home || strings.HasPrefix(p, home+"/") || home == "/" {
		return p, nil
	}
	return "", fmt.Errorf("path is outside home directory")
}

func getSession(id string) *Session {
	sessionMutex.RLock()
	defer sessionMutex.RUnlock()
	if s, ok := sessionStore[id]; ok {
		s.LastAccess = time.Now()
		return s
	}
	return nil
}

// Cleanup expired sessions
func init() {
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			sessionMutex.Lock()
			for id, s := range sessionStore {
				if time.Since(s.LastAccess) > 2*time.Hour {
					s.SFTPClient.Close()
					s.SSHClient.Close()
					delete(sessionStore, id)
					log.Printf("Session %s expired and closed", id)
				}
			}
			sessionMutex.Unlock()
		}
	}()
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type SSHCredentials struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"user"`
	AuthType string `json:"auth_type"`
	Password string `json:"pass"`
	Key      string `json:"key"`
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var creds SSHCredentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid credentials", 400)
		return
	}

	config, err := getSSHConfig(creds.Username, creds.AuthType, creds.Password, creds.Key)
	if err != nil {
		audit(r, "", "ssh_login_config_failed", false, err.Error())
		http.Error(w, "Auth config error: "+err.Error(), 400)
		return
	}

	addr := fmt.Sprintf("%s:%d", creds.Host, creds.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		audit(r, "", "ssh_login_failed", false, err.Error())
		http.Error(w, "Login failed: "+err.Error(), 401)
		return
	}

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		client.Close()
		http.Error(w, "SFTP error: "+err.Error(), 500)
		return
	}

	sessionID := uuid.New().String()
	session := &Session{
		ID:         sessionID,
		SSHClient:  client,
		SFTPClient: sftpClient,
		Username:   creds.Username,
		HomeRoot:   userHomeRoot(creds.Username),
		LastAccess: time.Now(),
	}

	sessionMutex.Lock()
	sessionStore[sessionID] = session
	sessionMutex.Unlock()
	audit(r, "", "ssh_login_success", true, creds.Username+"@"+addr)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"sid":       sessionID,
		"user":      session.Username,
		"home_root": session.HomeRoot,
	})
}

func main() {
	loadConfig()
	if globalConfig.WebAuthn.Enabled {
		if globalConfig.Admin.Path == "" {
			globalConfig.Admin.Path = "/admin"
		}
		if globalConfig.Admin.Enabled == false {
			globalConfig.Admin.Enabled = true
		}
		if globalConfig.WebAuthn.AdminUser == "" {
			globalConfig.WebAuthn.AdminUser = "admin"
		}
		initAuth()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/status", handleAuthStatus)
	mux.HandleFunc("/auth/login/begin", handleAuthLoginBegin)
	mux.HandleFunc("/auth/login/finish", handleAuthLoginFinish)
	mux.HandleFunc("/auth/register/begin", handleAuthRegisterBegin)
	mux.HandleFunc("/auth/register/finish", handleAuthRegisterFinish)
	mux.HandleFunc("/auth/logout", handleAuthLogout)
	mux.Handle("/admin/api/keys", requireAdmin(http.HandlerFunc(handleAdminKeys)))
	mux.Handle("/admin/api/key", requireAdmin(http.HandlerFunc(handleAdminKeyAction)))
	mux.Handle("/admin/api/audit", requireAdmin(http.HandlerFunc(handleAdminAudit)))
	mux.HandleFunc("/admin/", handleAdminGate)
	mux.HandleFunc("/admin", handleAdminGate)
	mux.Handle("/login", requireWebAuth(http.HandlerFunc(handleLogin)))
	mux.Handle("/ws", requireWebAuth(http.HandlerFunc(handleWebSocket)))
	mux.Handle("/upload", requireWebAuth(http.HandlerFunc(handleUpload)))
	mux.Handle("/sftp/list", requireWebAuth(http.HandlerFunc(handleSFTPList)))
	mux.Handle("/sftp/action", requireWebAuth(http.HandlerFunc(handleSFTPAction)))
	mux.Handle("/sftp/raw", requireWebAuth(http.HandlerFunc(handleSFTPRaw)))
	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"server_port":            globalConfig.ServerPort,
			"hosts":                  globalConfig.Hosts,
			"base_path":              globalConfig.BasePath,
			"disable_password_login": globalConfig.DisablePasswordLogin,
			"webauthn": map[string]any{
				"enabled": globalConfig.WebAuthn.Enabled,
			},
			"admin": map[string]any{
				"enabled": globalConfig.Admin.Enabled,
				"path":    globalConfig.Admin.Path,
			},
		})
	})
	mux.Handle("/", http.FileServer(http.Dir("./static")))

	handler := loggingMiddleware(pathRewriteMiddleware(mux))
	fmt.Printf("GgySSH server starting on :%s...\n", globalConfig.ServerPort)
	if err := http.ListenAndServe(":"+globalConfig.ServerPort, handler); err != nil {
		log.Fatal(err)
	}
}

func handleSFTPList(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SID  string `json:"sid"`
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", 400)
		return
	}

	session := getSession(req.SID)
	if session == nil {
		http.Error(w, "Session expired", 401)
		return
	}

	normalizedPath, normErr := normalizePathWithinHome(session, req.Path)
	if normErr != nil {
		http.Error(w, normErr.Error(), http.StatusForbidden)
		return
	}

	files, err := session.SFTPClient.ReadDir(normalizedPath)
	if err != nil {
		http.Error(w, "ReadDir error: "+err.Error(), 500)
		return
	}

	var result []FileInfo = []FileInfo{}
	for _, f := range files {
		result = append(result, FileInfo{
			Name:  f.Name(),
			Size:  f.Size(),
			IsDir: f.IsDir(),
			Mode:  f.Mode().String(),
			Time:  f.ModTime().Format("2006-01-02 15:04:05"),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleSFTPRaw(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sid")
	filePath := r.URL.Query().Get("path")
	fileName := r.URL.Query().Get("name")

	session := getSession(sid)
	if session == nil {
		http.Error(w, "Session expired", 401)
		return
	}

	normalizedPath, normErr := normalizePathWithinHome(session, filePath)
	if normErr != nil {
		http.Error(w, normErr.Error(), http.StatusForbidden)
		return
	}

	src, err := session.SFTPClient.Open(normalizedPath)
	if err != nil {
		http.Error(w, "Open error: "+err.Error(), 500)
		return
	}
	defer src.Close()

	ext := strings.ToLower(path.Ext(normalizedPath))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	switch ext {
	case ".jpg", ".jpeg":
		w.Header().Set("Content-Type", "image/jpeg")
	case ".png":
		w.Header().Set("Content-Type", "image/png")
	case ".gif":
		w.Header().Set("Content-Type", "image/gif")
	case ".webp":
		w.Header().Set("Content-Type", "image/webp")
	case ".mp4":
		w.Header().Set("Content-Type", "video/mp4")
	case ".mp3":
		w.Header().Set("Content-Type", "audio/mpeg")
	case ".pdf":
		w.Header().Set("Content-Type", "application/pdf")
	}

	if fileName != "" {
		w.Header().Set("Content-Disposition", "inline; filename*=UTF-8''"+url.PathEscape(fileName))
	} else {
		w.Header().Set("Content-Disposition", "inline; filename*=UTF-8''"+url.PathEscape(path.Base(normalizedPath)))
	}

	if w.Header().Get("Content-Type") == "" {
		guessed := mime.TypeByExtension(ext)
		if guessed == "" {
			guessed = "application/octet-stream"
		}
		w.Header().Set("Content-Type", guessed)
	}

	io.Copy(w, src)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sid")
	session := getSession(sid)
	if session == nil {
		http.Error(w, "Session expired", 401)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}
	defer conn.Close()

	sshSession, err := session.SSHClient.NewSession()
	if err != nil {
		return
	}
	defer sshSession.Close()

	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := sshSession.RequestPty("xterm-256color", 40, 80, modes); err != nil {
		return
	}

	stdin, _ := sshSession.StdinPipe()
	stdout, _ := sshSession.StdoutPipe()
	stderr, _ := sshSession.StderrPipe()
	if err := sshSession.Shell(); err != nil {
		return
	}

	wsOut := &wsWriter{
		conn: conn,
		mu:   &sync.Mutex{},
	}

	var wg sync.WaitGroup
	wg.Add(4)
	go func() {
		defer wg.Done()
		readWebSocketInput(conn, stdin, sshSession)
	}()
	go func() { defer wg.Done(); io.Copy(wsOut, stdout) }()
	go func() { defer wg.Done(); io.Copy(wsOut, stderr) }()
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			wsOut.mu.Lock()
			err := conn.WriteMessage(websocket.PingMessage, []byte{})
			wsOut.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	wg.Wait()
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if err := r.ParseMultipartForm(100 << 20); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	sid := r.FormValue("sid")
	session := getSession(sid)
	if session == nil {
		http.Error(w, "Session expired", 401)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "File error", 400)
		return
	}
	defer file.Close()

	targetPath := r.FormValue("path")
	if targetPath == "" {
		http.Error(w, "Path is required", 400)
		return
	}
	normalizedPath, normErr := normalizePathWithinHome(session, targetPath)
	if normErr != nil {
		http.Error(w, normErr.Error(), http.StatusForbidden)
		return
	}

	targetDir := path.Dir(normalizedPath)
	if targetDir != "." && targetDir != "/" {
		if err := session.SFTPClient.MkdirAll(targetDir); err != nil {
			http.Error(w, "Mkdir error: "+err.Error(), 500)
			return
		}
	}

	dst, err := session.SFTPClient.Create(normalizedPath)
	if err != nil {
		http.Error(w, "Create error: "+err.Error(), 500)
		return
	}
	defer dst.Close()

	io.Copy(dst, file)
	log.Printf("Uploaded %s to %s", header.Filename, normalizedPath)
	fmt.Fprint(w, "Success")
}

func handleSFTPAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SID       string `json:"sid"`
		Action    string `json:"action"`
		Path      string `json:"path"`
		NewPath   string `json:"new_path"`
		Content   string `json:"content"`
		Overwrite bool   `json:"overwrite"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", 400)
		return
	}

	session := getSession(req.SID)
	if session == nil {
		http.Error(w, "Session expired", 401)
		return
	}

	resolvePath := func(input string) (string, bool) {
		p, err := normalizePathWithinHome(session, input)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return "", false
		}
		return p, true
	}

	var err error
	switch req.Action {
	case "delete":
		p, ok := resolvePath(req.Path)
		if !ok {
			return
		}
		if p == path.Clean(session.HomeRoot) && p != "/" {
			http.Error(w, "Refuse to delete home root", http.StatusForbidden)
			return
		}
		err = recursiveDelete(session.SFTPClient, p)
	case "rename":
		srcPath, ok := resolvePath(req.Path)
		if !ok {
			return
		}
		dstPath, ok := resolvePath(req.NewPath)
		if !ok {
			return
		}
		err = session.SFTPClient.Rename(srcPath, dstPath)
	case "mkdir":
		p, ok := resolvePath(req.Path)
		if !ok {
			return
		}
		err = session.SFTPClient.MkdirAll(p)
	case "read_text":
		p, ok := resolvePath(req.Path)
		if !ok {
			return
		}
		f, openErr := session.SFTPClient.Open(p)
		if openErr != nil {
			http.Error(w, openErr.Error(), 500)
			return
		}
		defer f.Close()
		b, readErr := io.ReadAll(f)
		if readErr != nil {
			http.Error(w, readErr.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"content": string(b),
		})
		return
	case "write_text":
		p, ok := resolvePath(req.Path)
		if !ok {
			return
		}
		if !req.Overwrite {
			if _, statErr := session.SFTPClient.Stat(p); statErr == nil {
				http.Error(w, "File exists", http.StatusConflict)
				return
			}
		}
		f, openErr := session.SFTPClient.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if openErr != nil {
			http.Error(w, openErr.Error(), 500)
			return
		}
		if _, writeErr := f.Write([]byte(req.Content)); writeErr != nil {
			_ = f.Close()
			http.Error(w, writeErr.Error(), 500)
			return
		}
		f.Close()
	default:
		http.Error(w, "Unknown action", 400)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fmt.Fprint(w, "Success")
}

func recursiveDelete(c *sftp.Client, remotePath string) error {
	info, err := c.Stat(remotePath)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return c.Remove(remotePath)
	}
	files, err := c.ReadDir(remotePath)
	if err != nil {
		return err
	}
	for _, f := range files {
		subPath := path.Join(remotePath, f.Name())
		err = recursiveDelete(c, subPath)
		if err != nil {
			return err
		}
	}
	return c.RemoveDirectory(remotePath)
}
