package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MaxPayloadSize = 4096
	DBPath         = "./chatapp.db"
	PoWDifficulty  = 4
)

type Client struct {
	conn            net.Conn
	username        string
	currentCh       string
	isAuthenticated bool
	userID          int
}

type Server struct {
	clients   map[net.Conn]*Client
	channels  map[string]map[net.Conn]*Client
	mu        sync.Mutex
	dbManager *DBManager
	listener  net.Listener
}

func NewServer(db *DBManager) *Server {
	return &Server{
		clients:  make(map[net.Conn]*Client),
		channels: make(map[string]map[net.Conn]*Client),
	}
}

func main() {
	bindPort := "55555"
	if len(os.Args) >= 2 {
		bindPort = os.Args[1]
	}

	dbManager, err := InitDB(DBPath)
	if err != nil {
		log.Fatalf("Init failed: %v", err)
	}
	server := NewServer(dbManager)
	server.dbManager = dbManager

	_, _ = dbManager.db.Exec("DELETE FROM messages WHERE timestamp < datetime('now', '-30 days')")

	fullBindAddr := "0.0.0.0:" + bindPort
	listener, err := net.Listen("tcp", fullBindAddr)
	if err != nil {
		log.Fatalf("Bind failed on %s: %v", fullBindAddr, err)
	}
	server.listener = listener
	defer listener.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("[%s] SERVER: Listening publicly on port %s\n", timestamp, bindPort)

	go server.handleServerConsole()

	for {
		conn, err := listener.Accept()
		if err != nil {
			break
		}
		go server.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	s.mu.Lock()
	client := &Client{conn: conn}
	s.clients[conn] = client
	s.mu.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("[%s] CLIENT: Connection established via socket endpoint\n", timestamp)

	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if err != nil || n != 4096 {
			break
		}

		message := string(buffer[:])
		zeroIdx := strings.Index(message, "\x00")
		if zeroIdx != -1 {
			message = message[:zeroIdx]
		}

		message = strings.TrimSpace(message)
		if message == "" {
			continue
		}

		if strings.HasPrefix(message, "/") {
			s.handleCommand(client, message)
		} else {
			if client.isAuthenticated && client.currentCh != "" {
				s.broadcastToChannel(client, message)
			}
		}
	}

	s.mu.Lock()
	if client.currentCh != "" && s.channels[client.currentCh] != nil {
		delete(s.channels[client.currentCh], conn)
	}
	delete(s.clients, conn)
	s.mu.Unlock()

	timestamp = time.Now().Format("2006-01-02 15:04:05")
	if client.isAuthenticated {
		fmt.Printf("[%s] USER (%d): Session closed\n", timestamp, client.userID)
	} else {
		fmt.Printf("[%s] CLIENT: Session closed\n", timestamp)
	}
}

func (s *Server) broadcastToChannel(client *Client, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	formattedMsg := fmt.Sprintf("[%s] %s: %s\n", timestamp, client.username, msg)

	var historyEnabled int
	_ = s.dbManager.db.QueryRow("SELECT history_enabled FROM channels WHERE name = ?", client.currentCh).Scan(&historyEnabled)
	if historyEnabled == 1 {
		var chID int
		_ = s.dbManager.db.QueryRow("SELECT id FROM channels WHERE name = ?", client.currentCh).Scan(&chID)
		_, _ = s.dbManager.db.Exec("INSERT INTO messages (channel_id, sender_id, payload, timestamp) VALUES (?, ?, ?, ?)", chID, client.userID, msg, timestamp)
	}

	paddedOut := make([]byte, 4096)
	copy(paddedOut, []byte(formattedMsg))

	for conn := range s.channels[client.currentCh] {
		if conn != client.conn {
			conn.Write(paddedOut)
		}
	}
}

func (s *Server) handleServerConsole() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}

		parts := strings.Split(text, " ")
		cmd := parts[0]

		switch cmd {
		case "wipe":
			s.mu.Lock()
			_, _ = s.dbManager.db.Exec("DELETE FROM channel_members;")
			_, _ = s.dbManager.db.Exec("DELETE FROM messages;")
			_, _ = s.dbManager.db.Exec("DELETE FROM channels;")
			_, _ = s.dbManager.db.Exec("DELETE FROM users;")
			_, _ = s.dbManager.db.Exec("VACUUM;")

			s.channels = make(map[string]map[net.Conn]*Client)

			warnMsg := "User: Unauthenticated, Channel: None\n"
			paddedWarn := make([]byte, 4096)
			copy(paddedWarn, []byte(warnMsg))

			for conn, c := range s.clients {
				c.isAuthenticated = false
				c.username = "Unauthenticated"
				c.currentCh = ""
				c.userID = 0
				_, _ = conn.Write(paddedWarn)
			}
			s.mu.Unlock()

			timestamp := time.Now().Format("2006-01-02 15:04:05")
			fmt.Printf("[%s] SERVER: All client data wiped, database vacuumed, sessions reset.\n", timestamp)

		case "status":
			s.mu.Lock()
			activeClients := len(s.clients)
			s.mu.Unlock()

			dbStatus := "CONNECTED"
			if err := s.dbManager.db.Ping(); err != nil {
				dbStatus = "DISCONNECTED"
			}

			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			memAllocatedMB := float64(m.Alloc) / 1024 / 1024

			fmt.Printf("DB Status: %s\n", dbStatus)
			fmt.Printf("Process RAM: %.2f MB\n", memAllocatedMB)
			fmt.Printf("Active Clients: %d\n", activeClients)

		case "shutdown":
			countdown := 0
			if len(parts) >= 2 {
				if val, err := strconv.Atoi(parts[1]); err == nil && val > 0 {
					countdown = val
				}
			}

			if countdown > 0 {
				for i := countdown; i > 0; i-- {
					warnMsg := fmt.Sprintf("<!> SYSTEM: Server shutting down in %d seconds...\n", i)
					paddedWarn := make([]byte, 4096)
					copy(paddedWarn, []byte(warnMsg))

					s.mu.Lock()
					for conn, c := range s.clients {
						if c.isAuthenticated {
							conn.Write(paddedWarn)
						}
					}
					s.mu.Unlock()

					time.Sleep(1 * time.Second)
				}
			}

			timestamp := time.Now().Format("2006-01-02 15:04:05")
			fmt.Printf("[%s] SERVER: Shutting down network drop instantly...\n", timestamp)

			s.mu.Lock()
			for conn := range s.clients {
				conn.Write(make([]byte, 4096))
				conn.Close()
			}
			s.mu.Unlock()

			s.listener.Close()
			os.Exit(0)

		case "restart":
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			fmt.Printf("[%s] SERVER: Executing quick restart loop sequence...\n", timestamp)

			s.mu.Lock()
			for conn := range s.clients {
				conn.Write(make([]byte, 4096))
				conn.Close()
			}
			s.mu.Unlock()

			s.listener.Close()
			os.Exit(0)

		case "say":
			if len(parts) < 2 {
				fmt.Println("Usage: say <your message text here>")
				continue
			}
			broadcastMsg := strings.Join(parts[1:], " ")
			formattedMessage := fmt.Sprintf("<!> SYSTEM: %s\n", broadcastMsg)
			paddedMsg := make([]byte, 4096)
			copy(paddedMsg, []byte(formattedMessage))

			s.mu.Lock()
			sentCount := 0
			for conn, c := range s.clients {
				if c.isAuthenticated {
					conn.Write(paddedMsg)
					sentCount++
				}
			}
			s.mu.Unlock()

			if sentCount > 0 {
				fmt.Printf("Message broadcasted to %d authenticated client(s).\n", sentCount)
			} else {
				fmt.Println("Broadcast aborted: No authenticated clients are online.")
			}

		default:
			fmt.Println("Server Commands: status, shutdown [seconds], restart, say <msg>, wipe")
		}
	}
}
