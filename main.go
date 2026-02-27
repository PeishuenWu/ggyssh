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

type WSControlMessage struct {
	Type string `json:"type"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

func loadConfig() {
	file, err := os.Open("config.json")
	if err != nil {
		log.Println("Config file not found, using defaults")
		globalConfig = Config{
			ServerPort:     "8080",
			DefaultSSHHost: "127.0.0.1",
			DefaultSSHPort: 22,
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
		
		// Log the public key for the user to verify against authorized_keys
		pubKey := signer.PublicKey()
		authorizedKey := string(ssh.MarshalAuthorizedKey(pubKey))
		log.Printf("Parsed Key Type: %s", pubKey.Type())
		log.Printf("Public Key for authorized_keys:\n%s", authorizedKey)
		
		auth = append(auth, ssh.PublicKeys(signer))
	} else {
		auth = append(auth, ssh.Password(pass))
	}

	return &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, nil
}

func main() {
	loadConfig()

	mux := http.NewServeMux()
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

func getSFTPClient(creds SSHCredentials) (*ssh.Client, *sftp.Client, error) {
	config, err := getSSHConfig(creds.Username, creds.AuthType, creds.Password, creds.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("auth config error: %v", err)
	}

	addr := fmt.Sprintf("%s:%d", creds.Host, creds.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, nil, fmt.Errorf("ssh dial error: %v", err)
	}

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		client.Close()
		return nil, nil, fmt.Errorf("sftp client error: %v", err)
	}

	return client, sftpClient, nil
}

type FileInfo struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	IsDir bool   `json:"is_dir"`
	Mode  string `json:"mode"`
	Time  string `json:"time"`
}

func handleSFTPList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req struct {
		SSHCredentials
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", 400)
		return
	}

	client, sftpClient, err := getSFTPClient(req.SSHCredentials)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer client.Close()
	defer sftpClient.Close()

	if req.Path == "" {
		req.Path = "."
	}

	files, err := sftpClient.ReadDir(req.Path)
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
	// Support both GET (for tags like <img>) and POST (for initial setup)
	// But for simple previewing, GET with query params is easier for media tags.
	// For security in a real app, we might use temporary tokens.
	
	path := r.URL.Query().Get("path")
	host := r.URL.Query().Get("host")
	portStr := r.URL.Query().Get("port")
	user := r.URL.Query().Get("user")
	authType := r.URL.Query().Get("auth_type")
	pass := r.URL.Query().Get("pass")
	key := r.URL.Query().Get("key")

	port := 22
	fmt.Sscanf(portStr, "%d", &port)

	creds := SSHCredentials{
		Host:     host,
		Port:     port,
		Username: user,
		AuthType: authType,
		Password: pass,
		Key:      key,
	}

	client, sftpClient, err := getSFTPClient(creds)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer client.Close()
	defer sftpClient.Close()

	src, err := sftpClient.Open(path)
	if err != nil {
		http.Error(w, "Open error: "+err.Error(), 500)
		return
	}
	defer src.Close()

	// Try to detect content type from extension
	ext := path[len(path)-4:]
	switch ext {
	case ".jpg", "jpeg":
		w.Header().Set("Content-Type", "image/jpeg")
	case ".png":
		w.Header().Set("Content-Type", "image/png")
	case ".gif":
		w.Header().Set("Content-Type", "image/gif")
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
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}
	defer conn.Close()

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
		conn.WriteMessage(websocket.TextMessage, []byte("\r\nAuth config error: "+err.Error()+"\r\n"))
		return
	}

	addr := fmt.Sprintf("%s:%d", creds.Host, creds.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		log.Printf("SSH Dial error to %s: %v", addr, err)
		conn.WriteMessage(websocket.TextMessage, []byte("\r\nSSH Dial error: "+err.Error()+"\r\n"))
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return
	}
	defer session.Close()

	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := session.RequestPty("xterm-256color", 40, 80, modes); err != nil {
		return
	}

	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()
	if err := session.Shell(); err != nil {
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
		readWebSocketInput(conn, stdin, session)
	}()
	go func() { defer wg.Done(); io.Copy(wsOut, stdout) }()
	go func() { defer wg.Done(); io.Copy(wsOut, stderr) }()
	wg.Wait()
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

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if err := r.ParseMultipartForm(100 << 20); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "File error", 400)
		return
	}
	defer file.Close()

	port, _ := fmt.Sscanf(r.FormValue("port"), "%d")
	if port == 0 {
		port = 22
	}

	creds := SSHCredentials{
		Host:     r.FormValue("host"),
		Port:     port,
		Username: r.FormValue("user"),
		AuthType: r.FormValue("auth_type"),
		Password: r.FormValue("pass"),
		Key:      r.FormValue("key"),
	}

	client, sftpClient, err := getSFTPClient(creds)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer client.Close()
	defer sftpClient.Close()

	targetPath := r.FormValue("path")
	if targetPath == "" {
		http.Error(w, "Path is required", 400)
		return
	}
	targetDir := path.Dir(targetPath)
	if targetDir != "." && targetDir != "/" {
		if err := sftpClient.MkdirAll(targetDir); err != nil {
			http.Error(w, "Mkdir error: "+err.Error(), 500)
			return
		}
	}

	dst, err := sftpClient.Create(targetPath)
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
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req struct {
		SSHCredentials
		Action  string `json:"action"`
		Path    string `json:"path"`
		NewPath string `json:"new_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", 400)
		return
	}

	client, sftpClient, err := getSFTPClient(req.SSHCredentials)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer client.Close()
	defer sftpClient.Close()

	switch req.Action {
	case "delete":
		err = sftpClient.Remove(req.Path)
		if err != nil {
			// Try removing directory
			err = sftpClient.RemoveDirectory(req.Path)
		}
	case "rename":
		err = sftpClient.Rename(req.Path, req.NewPath)
	case "mkdir":
		err = sftpClient.MkdirAll(req.Path)
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
