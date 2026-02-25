package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
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

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(stdin, &wsReader{conn}) }()
	go func() { defer wg.Done(); io.Copy(&wsWriter{conn}, io.MultiReader(stdout, stderr)) }()
	wg.Wait()
}

type wsReader struct{ conn *websocket.Conn }
func (r *wsReader) Read(p []byte) (int, error) {
	_, msg, err := r.conn.ReadMessage()
	if err != nil {
		return 0, err
	}
	return copy(p, msg), nil
}

type wsWriter struct{ conn *websocket.Conn }
func (w *wsWriter) Write(p []byte) (int, error) {
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

	creds := SSHCredentials{
		Host:     r.FormValue("host"),
		Port:     22,
		Username: r.FormValue("user"),
		AuthType: r.FormValue("auth_type"),
		Password: r.FormValue("pass"),
		Key:      r.FormValue("key"),
	}
	fmt.Sscanf(r.FormValue("port"), "%d", &creds.Port)

	config, err := getSSHConfig(creds.Username, creds.AuthType, creds.Password, creds.Key)
	if err != nil {
		http.Error(w, "Auth error: "+err.Error(), 400)
		return
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", creds.Host, creds.Port), config)
	if err != nil {
		http.Error(w, "SSH error: "+err.Error(), 500)
		return
	}
	defer client.Close()

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		http.Error(w, "SFTP error", 500)
		return
	}
	defer sftpClient.Close()

	dst, err := sftpClient.Create(r.FormValue("path"))
	if err != nil {
		http.Error(w, "Create error: "+err.Error(), 500)
		return
	}
	defer dst.Close()

	io.Copy(dst, file)
	log.Printf("Uploaded %s to %s", header.Filename, r.FormValue("path"))
	fmt.Fprint(w, "Success")
}
