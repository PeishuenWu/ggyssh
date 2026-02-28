package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	ServerPort     string `json:"server_port"`
	DefaultSSHHost string `json:"default_ssh_host"`
	DefaultSSHPort int    `json:"default_ssh_port"`
}

var globalConfig Config

// Session management
type Session struct {
	ID         string
	SSHClient  *ssh.Client
	SFTPClient *sftp.Client
	LastAccess time.Time
}

var (
	sessionStore = make(map[string]*Session)
	sessionMutex sync.RWMutex
)

func createSession(creds SSHCredentials) (*Session, error) {
	config, err := getSSHConfig(creds.Username, creds.AuthType, creds.Password, creds.Key)
	if err != nil {
		return nil, err
	}

	addr := fmt.Sprintf("%s:%d", creds.Host, creds.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		client.Close()
		return nil, err
	}

	sessionID := uuid.New().String()
	session := &Session{
		ID:         sessionID,
		SSHClient:  client,
		SFTPClient: sftpClient,
		LastAccess: time.Now(),
	}

	sessionMutex.Lock()
	sessionStore[sessionID] = session
	sessionMutex.Unlock()

	return session, nil
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

	session, err := createSession(creds)
	if err != nil {
		http.Error(w, "Login failed: "+err.Error(), 401)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"sid": session.ID})
}

func main() {
	loadConfig()

	mux := http.NewServeMux()
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/ws", handleWebSocket)
	mux.HandleFunc("/upload", handleUpload)
	mux.HandleFunc("/sftp/list", handleSFTPList)
	mux.HandleFunc("/sftp/action", handleSFTPAction)
	mux.HandleFunc("/sftp/raw", handleSFTPRaw)
	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(globalConfig)
	})
	mux.Handle("/", http.FileServer(http.Dir("./static")))

	handler := loggingMiddleware(mux)
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

	if req.Path == "" {
		req.Path = "."
	}

	files, err := session.SFTPClient.ReadDir(req.Path)
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

	session := getSession(sid)
	if session == nil {
		http.Error(w, "Session expired", 401)
		return
	}

	src, err := session.SFTPClient.Open(filePath)
	if err != nil {
		http.Error(w, "Open error: "+err.Error(), 500)
		return
	}
	defer src.Close()

	ext := path.Ext(filePath)
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

	io.Copy(w, src)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sid")
	session := getSession(sid)
	if session == nil {
		// Try legacy mode if no SID (for initial compatibility or separate login)
		log.Println("WS: No session ID provided")
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}
	defer conn.Close()

	var sshClient *ssh.Client
	if session != nil {
		sshClient = session.SSHClient
	} else {
		// Legacy: Expect credentials in first message
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var creds SSHCredentials
		if err := json.Unmarshal(msg, &creds); err != nil {
			conn.WriteMessage(websocket.TextMessage, []byte("\r\nInvalid credentials\r\n"))
			return
		}
		config, err := getSSHConfig(creds.Username, creds.AuthType, creds.Password, creds.Key)
		if err != nil {
			conn.WriteMessage(websocket.TextMessage, []byte("\r\nAuth error: "+err.Error()+"\r\n"))
			return
		}
		client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", creds.Host, creds.Port), config)
		if err != nil {
			conn.WriteMessage(websocket.TextMessage, []byte("\r\nDial error: "+err.Error()+"\r\n"))
			return
		}
		sshClient = client
		defer client.Close()
	}

	sshSession, err := sshClient.NewSession()
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
	wg.Add(3)
	go func() {
		defer wg.Done()
		readWebSocketInput(conn, stdin, sshSession)
	}()
	go func() { defer wg.Done(); io.Copy(wsOut, stdout) }()
	go func() { defer wg.Done(); io.Copy(wsOut, stderr) }()
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
	targetDir := path.Dir(targetPath)
	if targetDir != "." && targetDir != "/" {
		if err := session.SFTPClient.MkdirAll(targetDir); err != nil {
			http.Error(w, "Mkdir error: "+err.Error(), 500)
			return
		}
	}

	dst, err := session.SFTPClient.Create(targetPath)
	if err != nil {
		http.Error(w, "Create error: "+err.Error(), 500)
		return
	}
	defer dst.Close()

	io.Copy(dst, file)
	log.Printf("Uploaded %s to %s", header.Filename, targetPath)
	fmt.Fprint(w, "Success")
}

func handleSFTPAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SID     string `json:"sid"`
		Action  string `json:"action"`
		Path    string `json:"path"`
		NewPath string `json:"new_path"`
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

	var err error
	switch req.Action {
	case "delete":
		err = recursiveDelete(session.SFTPClient, req.Path)
	case "rename":
		err = session.SFTPClient.Rename(req.Path, req.NewPath)
	case "mkdir":
		err = session.SFTPClient.MkdirAll(req.Path)
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
