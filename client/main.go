package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	VaultFileName = "./pass.dat"
	PBKDF2Rounds  = 100000
)

var masterKey []byte
var currentRoomKey []byte
var activeConn net.Conn
var inChannel bool
var localUsername string = "Unauthenticated"
var currentServerAddr string = "Disconnected"
var currentChName string = ""

func pbkdf2Simple(password string, salt []byte, iterations int) []byte {
	h := sha256.New()
	hashLen := h.Size()
	out := make([]byte, hashLen)

	U := append([]byte(password), salt...)
	U = append(U, 0, 0, 0, 1)

	h.Reset()
	h.Write(U)
	copy(out, h.Sum(nil))

	U = make([]byte, hashLen)
	copy(U, out)

	for i := 1; i < iterations; i++ {
		h.Reset()
		h.Write(U)
		U = h.Sum(nil)
		for j := 0; j < hashLen; j++ {
			out[j] ^= U[j]
		}
	}
	return out
}

func printHelpMenu() {
	menu := "------------------------------------------- Commands -------------------------------------------\n" +
		" /connect <ip> <port>                    - Connect to a node interface (switches host automatically)\n" +
		" /register <user> <pass>                 - Create a new account on connected node\n" +
		" /login <user> <pass>                    - Log into your account\n" +
		" /info                                   - View current user and active channel\n" +
		" /who                                    - View users inside your current channel\n" +
		" /create <channel> [pub]                 - Create a channel (Private by default)\n" +
		" /privacy <channel> <pub|priv>           - Adjust visibility settings\n" +
		" /privacy <channel> memory <on|off>      - Toggle rolling 30-day E2EE memory\n" +
		" /join <channel>                         - Enter a chat channel\n" +
		" /leave                                  - Exit your current chat channel\n" +
		" /invite <channel> <username>            - Authorize user for private room\n" +
		" /channels                               - View channels available to you\n" +
		" /clear                                  - Clear terminal framework display\n" +
		" /exit                                   - Terminate application thread instantly\n" +
		"------------------------------------------------------------------------------------------------\n"
	fmt.Print(menu)
}

func printPromptPrefix() {
	if inChannel && currentChName != "" {
		fmt.Printf("%s> ", currentChName)
	} else {
		fmt.Print("> ")
	}
}

func startNetworkReader(conn net.Conn) {
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, err := conn.Read(buffer)
			if err != nil || n != 4096 {
				if activeConn == conn {
					fmt.Println("\nNetwork stream disconnected from server.")
					activeConn = nil
					inChannel = false
					currentRoomKey = nil
					currentChName = ""
					currentServerAddr = "Disconnected"
					printPromptPrefix()
				}
				return
			}

			msgStr := string(buffer[:])
			zeroIdx := strings.Index(msgStr, "\x00")
			if zeroIdx != -1 {
				msgStr = msgStr[:zeroIdx]
			}

			msgTrimmed := strings.TrimSpace(msgStr)
			if msgTrimmed == "" {
				continue
			}

			if strings.HasPrefix(msgTrimmed, "[") && strings.Contains(msgTrimmed, ": ") {
				parts := strings.SplitN(msgTrimmed, ": ", 2)
				header := parts[0]
				payload := parts[1]

				if inChannel && len(currentRoomKey) > 0 {
					decrypted, err := DecryptMessage(payload, currentRoomKey)
					if err == nil {
						fmt.Printf("\r%s: %s\n", header, decrypted)
						printPromptPrefix()
						continue
					}
					fmt.Printf("\r%s: [Encrypted]\n", header)
					printPromptPrefix()
					continue
				}
			}

			if strings.Contains(msgTrimmed, "Channel does not exist") || strings.Contains(msgTrimmed, "Access denied") {
				inChannel = false
				currentChName = ""
				currentRoomKey = nil
			}

			fmt.Printf("\r%s\n", msgTrimmed)
			printPromptPrefix()
		}
	}()
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Print("Enter Password to unlock (or type /purge): ")
	if !scanner.Scan() {
		return
	}
	password := strings.TrimSpace(scanner.Text())

	if strings.ToLower(password) == "/purge" {
		fmt.Print("WARNING: This will completely delete local application vault configuration. Type 'CONFIRM': ")
		if scanner.Scan() {
			conf := strings.TrimSpace(scanner.Text())
			if conf == "CONFIRM" {
				_ = os.Remove(VaultFileName)
				log.Fatalf("Vault configuration purged successfully. Exiting.")
			}
		}
		log.Fatalf("Purge aborted. Exiting.")
	}

	if len(password) < 4 {
		log.Fatalf("Password too weak. Exiting.")
	}

	fixedSalt := []byte("traffic_analysis_defense_salt_constants")
	inputHash := pbkdf2Simple(password, fixedSalt, PBKDF2Rounds)
	isPanicAuth := false

	if _, err := os.Stat(VaultFileName); os.IsNotExist(err) {
		fmt.Print("Setup Plausible Deniability Panic Password: ")
		if !scanner.Scan() {
			return
		}
		panicPass := strings.TrimSpace(scanner.Text())
		panicHash := pbkdf2Simple(panicPass, fixedSalt, PBKDF2Rounds)

		combinedVault := make([]byte, 64)
		copy(combinedVault[0:32], inputHash)
		copy(combinedVault[32:64], panicHash)

		err = os.WriteFile(VaultFileName, combinedVault, 0600)
		if err != nil {
			log.Fatalf("Failed to initialize vault file: %v", err)
		}
		fmt.Println("Vault configurations initialized successfully into pass.dat archive.")
	} else {
		savedVault, err := os.ReadFile(VaultFileName)
		if err != nil {
			log.Fatalf("Failed to read vault file: %v", err)
		}
		if len(savedVault) < 64 {
			log.Fatalf("Vault file structurally corrupted. Run /purge and reset configurations.")
		}

		savedMasterHash := savedVault[0:32]
		savedPanicHash := savedVault[32:64]

		if !bytes.Equal(inputHash, savedMasterHash) {
			if bytes.Equal(inputHash, savedPanicHash) {
				isPanicAuth = true
			} else {
				log.Fatalf("Authentication failed: Invalid Password.")
			}
		}
	}

	masterKey = inputHash
	fmt.Println("Application unlocked.")
	fmt.Println("Status: Local session offline. Use /connect <ip> <port> to clear network route.\n")

	uuid, err := GetMachineUUID()
	if err != nil {
		uuid = "unknown-hwid"
	}

	printPromptPrefix()
	for scanner.Scan() {
		text := scanner.Text()
		text = strings.TrimSpace(text)
		if text == "" {
			printPromptPrefix()
			continue
		}

		lowerText := strings.ToLower(text)
		isCommand := strings.HasPrefix(text, "/")
		parts := strings.Split(text, " ")

		if !isCommand && inChannel {
			fmt.Print("\033[1A\033[2K")
		}

		if lowerText == "/exit" {
			if activeConn != nil {
				activeConn.Close()
			}
			fmt.Println("Session terminated cleanly. Exiting terminal shell framework.")
			os.Exit(0)
		}

		if lowerText == "/clear" {
			fmt.Print("\033[H\033[2J")
			printPromptPrefix()
			continue
		}

		if lowerText == "/help" {
			printHelpMenu()
			printPromptPrefix()
			continue
		}

		if parts[0] == "/connect" {
			if len(parts) < 3 {
				fmt.Println("Usage: /connect <ip> <port>")
				printPromptPrefix()
				continue
			}

			if activeConn != nil {
				activeConn.Close()
				activeConn = nil
				inChannel = false
				currentChName = ""
				currentRoomKey = nil
			}

			targetHost := parts[1] + ":" + parts[2]
			fmt.Printf("Connecting to node interface at %s...", targetHost)

			conn, err := net.DialTimeout("tcp", targetHost, 5*time.Second)
			if err != nil {
				fmt.Println("\nConnection failure: Target network endpoint unreachable.")
				currentServerAddr = "Disconnected"
				printPromptPrefix()
				continue
			}
			activeConn = conn
			currentServerAddr = targetHost
			fmt.Println(" Connected.")

			startNetworkReader(activeConn)

			if isPanicAuth {
				panicPayload := make([]byte, 4096)
				copy(panicPayload, []byte("/panic\n"))
				_, _ = activeConn.Write(panicPayload)
			}
			printPromptPrefix()
			continue
		}

		if lowerText == "/leave" {
			inChannel = false
			currentChName = ""
			currentRoomKey = nil
		}

		if isCommand {
			validCommands := map[string]bool{
				"/register": true, "/login": true, "/info": true, "/who": true,
				"/create": true, "/privacy": true, "/join": true, "/leave": true,
				"/invite": true, "/channels": true, "/clear": true, "/help": true,
				"/connect": true, "/exit": true,
			}
			if !validCommands[parts[0]] {
				fmt.Println("Unknown command. Type /help")
				printPromptPrefix()
				continue
			}
		}

		if parts[0] != "/connect" {
			if activeConn == nil {
				fmt.Println("Error: No active terminal connection routing path found. Run /connect first.")
				printPromptPrefix()
				continue
			}
			if !isCommand && !inChannel {
				fmt.Println("Unknown command. Type /help")
				printPromptPrefix()
				continue
			}
		} else {
			continue
		}

		if strings.HasPrefix(text, "/register ") {
			text = text + " " + uuid
		}

		if strings.HasPrefix(text, "/login ") {
			if len(parts) >= 2 {
				localUsername = parts[1]
			}
		}

		if strings.HasPrefix(text, "/join ") {
			if len(parts) >= 2 {
				targetRoomName := parts[1]
				fmt.Print("Room Password: ")
				if scanner.Scan() {
					roomPassword := strings.TrimSpace(scanner.Text())
					roomKeyHash := pbkdf2Simple(roomPassword, append(fixedSalt, []byte(targetRoomName)...), 1000)
					currentRoomKey = roomKeyHash
				}
				inChannel = true
				currentChName = targetRoomName
			}
		}

		outText := text
		if !strings.HasPrefix(text, "/") && inChannel && len(currentRoomKey) > 0 {
			encryptedPayload, err := EncryptMessage(text, currentRoomKey)
			if err == nil {
				outText = encryptedPayload
				timestamp := time.Now().Format("2006-01-02 15:04:05")
				fmt.Printf("[%s] %s: %s\n", timestamp, localUsername, text)
			} else {
				fmt.Println("Encryption error, aborting transmission.")
				printPromptPrefix()
				continue
			}
		}

		paddedPayload := make([]byte, 4096)
		copy(paddedPayload, []byte(outText+"\n"))

		_, err = activeConn.Write(paddedPayload)
		if err != nil {
			fmt.Println("Failed to pass framework payload data.")
			break
		}

		if !isCommand && inChannel {
			printPromptPrefix()
		}
	}
}

func GetMachineUUID() (string, error) {
	cmd := exec.Command("wmic", "csproduct", "get", "UUID")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		return "", fmt.Errorf("unexpected layout")
	}
	uuid := strings.TrimSpace(lines[1])
	return uuid, nil
}
