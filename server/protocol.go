package main

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

type Payload struct {
	TargetChannel    string            `json:"target_channel"`
	EncryptedPackets map[string]string `json:"encrypted_packets"`
}

func (s *Server) handleCommand(client *Client, cmd string) {
	parts := strings.Split(cmd, " ")
	if len(parts) == 0 {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	if strings.HasPrefix(parts[0], "/") {
		validCommands := map[string]bool{
			"/register": true, "/login": true, "/info": true, "/who": true,
			"/create": true, "/privacy": true, "/join": true, "/leave": true,
			"/invite": true, "/channels": true, "/clear": true, "/help": true,
			"/panic": true,
		}
		if !validCommands[parts[0]] {
			client.conn.Write(padPacket([]byte("Unknown command. Type /help\n")))
			return
		}
	} else {
		return
	}

	switch parts[0] {
	case "/panic":
		if !client.isAuthenticated {
			client.conn.Write(padPacket([]byte("Authenticated access required\n")))
			return
		}
		_, _ = s.dbManager.db.Exec("DELETE FROM messages WHERE sender_id = ?", client.userID)
		_, _ = s.dbManager.db.Exec("DELETE FROM channel_members WHERE user_id = ?", client.userID)
		_, _ = s.dbManager.db.Exec("DELETE FROM channels WHERE owner_id = ?", client.userID)
		_, _ = s.dbManager.db.Exec("DELETE FROM users WHERE id = ?", client.userID)

		fmt.Printf("[%s] PANIC PURGE EXECUTION: Identity records for User ID %d fully destroyed.\n", timestamp, client.userID)
		client.conn.Write(padPacket([]byte("Authenticated. Use /join <channel> to chat\n")))

	case "/register":
		if len(parts) < 4 {
			client.conn.Write(padPacket([]byte("Usage: /register <user> <pass>\n")))
			return
		}
		username := parts[1]
		password := parts[2]
		rawHWID := parts[3]

		userRegex, _ := regexp.Compile("^[a-zA-Z0-9_-]+$")
		if !userRegex.MatchString(username) {
			client.conn.Write(padPacket([]byte("Registration failed: Username must contain only alphanumeric characters, dashes, or underscores\n")))
			return
		}

		lowerUser := strings.ToLower(username)
		lowerPass := strings.ToLower(password)
		forbiddenNames := map[string]bool{
			"server": true, "client": true, "admin": true,
			"root": true, "user": true, "mod": true,
			"system": true, "owner": true, "support": true,
			"none": true, "true": true, "false": true,
		}
		if forbiddenNames[lowerUser] || forbiddenNames[lowerPass] {
			client.conn.Write(padPacket([]byte("Registration failed: Username or password contains a reserved system keyword\n")))
			return
		}

		maskedHWID := BlindHardwareID(rawHWID)

		err := s.dbManager.RegisterUser(username, password, maskedHWID)
		if err != nil {
			fmt.Printf("[%s] REGISTRATION FAILED: %s\n", timestamp, username)
			errMsg := "Registration failed"
			if strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
				errMsg = "Registration failed: Username is already taken"
			}
			client.conn.Write(padPacket([]byte(errMsg + "\n")))
			return
		}

		fmt.Printf("[%s] REGISTRATION: %s\n", timestamp, username)
		client.conn.Write(padPacket([]byte("Account created. You can now /login\n")))

	case "/login":
		if len(parts) < 3 {
			client.conn.Write(padPacket([]byte("Usage: /login <user> <pass>\n")))
			return
		}

		targetUser := parts[1]

		s.mu.Lock()
		for _, c := range s.clients {
			if c.isAuthenticated && strings.ToLower(c.username) == strings.ToLower(targetUser) {
				s.mu.Unlock()
				client.conn.Write(padPacket([]byte("Authentication failed: Account is already logged in\n")))
				return
			}
		}
		s.mu.Unlock()

		id, err := s.dbManager.AuthenticateUser(targetUser, parts[2])
		if err != nil {
			client.conn.Write(padPacket([]byte("Authentication failed\n")))
			return
		}
		client.userID = id
		client.username = targetUser
		client.isAuthenticated = true

		fmt.Printf("[%s] USER (%d): Logged in\n", timestamp, id)
		client.conn.Write(padPacket([]byte("Authenticated. Use /join <channel> to chat\n")))

	case "/create":
		if !client.isAuthenticated {
			client.conn.Write(padPacket([]byte("Must be logged in\n")))
			return
		}
		if len(parts) < 2 {
			client.conn.Write(padPacket([]byte("Usage: /create <channel> [pub]\n")))
			return
		}

		channelName := parts[1]

		matched, _ := regexp.MatchString("^[a-zA-Z0-9_-]+$", channelName)
		if !matched {
			client.conn.Write(padPacket([]byte("Channel creation failed: Name must contain only alphanumeric characters, dashes, or underscores\n")))
			return
		}

		lowerChan := strings.ToLower(channelName)
		if lowerChan == "none" || lowerChan == "true" || lowerChan == "false" {
			client.conn.Write(padPacket([]byte("Channel creation failed: Name is a reserved system keyword\n")))
			return
		}

		priv := 1
		if len(parts) == 3 && (parts[2] == "public" || parts[2] == "pub") {
			priv = 0
		}

		err := s.dbManager.CreateChannel(channelName, client.userID, priv)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				client.conn.Write(padPacket([]byte("Channel creation failed: A channel with this name already exists\n")))
			} else {
				client.conn.Write(padPacket([]byte("Channel creation failed\n")))
			}
			return
		}

		status := "private"
		if priv == 0 {
			status = "public"
		}
		client.conn.Write(padPacket([]byte("Channel created as " + status + "\n")))

	case "/join":
		if !client.isAuthenticated {
			client.conn.Write(padPacket([]byte("Must be logged in\n")))
			return
		}
		if len(parts) < 2 {
			client.conn.Write(padPacket([]byte("Usage: /join <channel>\n")))
			return
		}

		channelName := parts[1]

		var channelID int
		var isPrivate int
		var ownerID int
		err := s.dbManager.db.QueryRow("SELECT id, is_private, owner_id FROM channels WHERE name = ?", channelName).Scan(&channelID, &isPrivate, &ownerID)
		if err != nil {
			client.conn.Write(padPacket([]byte("Channel does not exist. Use /create first\n")))
			return
		}

		if isPrivate == 1 && ownerID != client.userID {
			var allowed int
			_ = s.dbManager.db.QueryRow("SELECT COUNT(*) FROM channel_members WHERE user_id = ? AND channel_id = ?", client.userID, channelID).Scan(&allowed)
			if allowed == 0 {
				client.conn.Write(padPacket([]byte("Access denied. This channel is private\n")))
				return
			}
		}

		s.mu.Lock()
		if s.channels[channelName] == nil {
			s.channels[channelName] = make(map[net.Conn]*Client)
		}
		if client.currentCh != "" && s.channels[client.currentCh] != nil {
			delete(s.channels[client.currentCh], client.conn)
		}
		client.currentCh = channelName
		s.channels[channelName][client.conn] = client
		s.mu.Unlock()

		var historyEnabled int
		_ = s.dbManager.db.QueryRow("SELECT history_enabled FROM channels WHERE name = ?", channelName).Scan(&historyEnabled)
		if historyEnabled == 1 {
			rows, err := s.dbManager.db.Query(`
				SELECT u.username, m.payload, m.timestamp 
				FROM messages m 
				JOIN users u ON m.sender_id = u.id 
				WHERE m.channel_id = ? 
				ORDER BY m.id ASC`, channelID)
			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var uName, payload, rawTime string
					if err := rows.Scan(&uName, &payload, &rawTime); err == nil {
						rawTime = strings.Replace(rawTime, "T", " ", 1)
						rawTime = strings.Replace(rawTime, "Z", "", 1)
						if len(rawTime) > 19 {
							rawTime = rawTime[:19]
						}
						client.conn.Write(padPacket([]byte(fmt.Sprintf("[%s] %s: %s\n", rawTime, uName, payload))))
					}
				}
			}
		}

	case "/leave":
		if !client.isAuthenticated {
			client.conn.Write(padPacket([]byte("Must be logged in\n")))
			return
		}
		if client.currentCh == "" {
			client.conn.Write(padPacket([]byte("You are not inside any channel\n")))
			return
		}

		s.mu.Lock()
		chName := client.currentCh
		if s.channels[chName] != nil {
			delete(s.channels[chName], client.conn)
		}
		client.currentCh = ""
		s.mu.Unlock()

		client.conn.Write(padPacket([]byte("Left channel " + chName + "\n")))

	case "/who":
		if !client.isAuthenticated {
			client.conn.Write(padPacket([]byte("Must be logged in\n")))
			return
		}
		if client.currentCh == "" {
			client.conn.Write(padPacket([]byte("You are not inside any channel\n")))
			return
		}

		s.mu.Lock()
		var activeUsers []string
		for _, peerClient := range s.channels[client.currentCh] {
			activeUsers = append(activeUsers, peerClient.username)
		}
		s.mu.Unlock()

		client.conn.Write(padPacket([]byte("Users in this channel: " + strings.Join(activeUsers, ", ") + "\n")))

	case "/invite":
		if !client.isAuthenticated {
			client.conn.Write(padPacket([]byte("Must be logged in\n")))
			return
		}
		if len(parts) < 3 {
			client.conn.Write(padPacket([]byte("Usage: /invite <channel> <username>\n")))
			return
		}
		targetChannel := parts[1]
		targetUser := parts[2]

		var channelID int
		var ownerID int
		err := s.dbManager.db.QueryRow("SELECT id, owner_id FROM channels WHERE name = ?", targetChannel).Scan(&channelID, &ownerID)
		if err != nil {
			client.conn.Write(padPacket([]byte("Channel not found\n")))
			return
		}
		if ownerID != client.userID {
			client.conn.Write(padPacket([]byte("Only the channel owner can modify settings\n")))
			return
		}

		var targetID int
		err = s.dbManager.db.QueryRow("SELECT id FROM users WHERE username = ?", targetUser).Scan(&targetID)
		if err != nil {
			client.conn.Write(padPacket([]byte("Could not invite user\n")))
			return
		}

		_, err = s.dbManager.db.Exec("INSERT OR IGNORE INTO channel_members (channel_id, user_id) VALUES (?, ?)", channelID, targetID)
		if err != nil {
			client.conn.Write(padPacket([]byte("Could not invite user\n")))
			return
		}
		client.conn.Write(padPacket([]byte(targetUser + " has been added to " + targetChannel + "\n")))

	case "/channels":
		if !client.isAuthenticated {
			client.conn.Write(padPacket([]byte("Must be logged in\n")))
			return
		}

		rows, err := s.dbManager.db.Query(`
			SELECT c.name, c.is_private, c.history_enabled, c.owner_id, c.id, u.username 
			FROM channels c
			JOIN users u ON c.owner_id = u.id
		`)
		if err != nil {
			client.conn.Write(padPacket([]byte("Could not retrieve channel list\n")))
			return
		}
		defer rows.Close()

		var sb strings.Builder
		sb.WriteString("-------------------------------------- Available Channels --------------------------------------\n")
		count := 0
		for rows.Next() {
			var name string
			var isPrivate int
			var historyEnabled int
			var ownerID int
			var channelID int
			var ownerName string
			if err := rows.Scan(&name, &isPrivate, &historyEnabled, &ownerID, &channelID, &ownerName); err == nil {
				if isPrivate == 1 && ownerID != client.userID {
					var isMember int
					_ = s.dbManager.db.QueryRow("SELECT COUNT(*) FROM channel_members WHERE channel_id = ? AND user_id = ?", client.userID, channelID).Scan(&isMember)
					if isMember == 0 {
						continue
					}
				}

				status := "public"
				if isPrivate == 1 {
					status = "private"
				}

				memoryString := "memory=off"
				if historyEnabled == 1 {
					memoryString = "memory=on"
				}

				sb.WriteString(fmt.Sprintf(" * %s [owner: %s, %s, %s]\n", name, ownerName, status, memoryString))
				count++
			}
		}
		if count == 0 {
			sb.WriteString(" No channels found.\n")
		}
		sb.WriteString("------------------------------------------------------------------------------------------------\n")
		client.conn.Write(padPacket([]byte(sb.String())))

	case "/privacy":
		if !client.isAuthenticated {
			client.conn.Write(padPacket([]byte("Must be logged in\n")))
			return
		}
		if len(parts) < 3 {
			client.conn.Write(padPacket([]byte("Usage: /privacy <channel> <pub|priv|memory on|memory off>\n")))
			return
		}
		chName := parts[1]
		setting := parts[2]

		var ownerID int
		err := s.dbManager.db.QueryRow("SELECT owner_id FROM channels WHERE name = ?", chName).Scan(&ownerID)
		if err != nil {
			client.conn.Write(padPacket([]byte("Channel not found\n")))
			return
		}
		if ownerID != client.userID {
			client.conn.Write(padPacket([]byte("Only the channel owner can modify settings\n")))
			return
		}

		if setting == "memory" && len(parts) == 4 {
			histVal := 0
			mode := "disabled"
			if parts[3] == "on" {
				histVal = 1
				mode = "enabled (rolling 30-day capacity)"
			} else if parts[3] != "off" {
				client.conn.Write(padPacket([]byte("Usage: /privacy <ch> memory <on|off>\n")))
				return
			}
			_, err = s.dbManager.db.Exec("UPDATE channels SET history_enabled = ? WHERE name = ?", histVal, chName)
			if err != nil {
				client.conn.Write(padPacket([]byte("Failed to update database\n")))
				return
			}
			if histVal == 0 {
				var chID int
				_ = s.dbManager.db.QueryRow("SELECT id FROM channels WHERE name = ?", chName).Scan(&chID)
				_, _ = s.dbManager.db.Exec("DELETE FROM messages WHERE channel_id = ?", chID)
			}
			client.conn.Write(padPacket([]byte("Channel message vault memory tracking " + mode + "\n")))
			return
		}

		privVal := 0
		if setting == "private" || setting == "priv" {
			privVal = 1
			setting = "private"
		} else if setting == "public" || setting == "pub" {
			privVal = 0
			setting = "public"
		} else {
			client.conn.Write(padPacket([]byte("Invalid option. Use pub, priv, or memory <on|off>\n")))
			return
		}

		_, err = s.dbManager.db.Exec("UPDATE channels SET is_private = ? WHERE name = ?", privVal, chName)
		if err != nil {
			client.conn.Write(padPacket([]byte("Failed to update database\n")))
			return
		}
		client.conn.Write(padPacket([]byte("Channel privacy updated to " + setting + "\n")))

	case "/info":
		u := client.username
		if u == "" {
			u = "Unauthenticated"
		}
		ch := client.currentCh
		if ch == "" {
			ch = "None"
		}
		client.conn.Write(padPacket([]byte(fmt.Sprintf("User: %s, Channel: %s\n", u, ch))))

	case "/help":
		menu := "------------------------------------------- Commands -------------------------------------------\n" +
			" /register <user> <pass>                 - Create a new account\n" +
			" /login <user> <pass>                    - Log into your account\n" +
			" /info                                   - View current user and active channel\n" +
			" /who                                    - View users inside your current channel\n" +
			" /create <channel> [pub]                 - Create a channel (Private by default)\n" +
			" /privacy <channel> <pub|priv>           - Adjust visibility settings\n" +
			" /privacy <channel> memory <on|off>      - Toggle rolling 30-day E2EE memory\n" +
			" /join <channel>                         - Enter a chat channel\n" +
			" /leave                                  - Exit your current chat channel\n" +
			" /invite <channel> <username>            - Authorize user for private room\n" +
			" /channels                               - View channels\n" +
			" /clear                                  - Clear terminal\n" +
			"------------------------------------------------------------------------------------------------\n"
		client.conn.Write(padPacket([]byte(menu)))

	default:
		client.conn.Write(padPacket([]byte("Unknown command. Type /help\n")))
	}
}

func padPacket(src []byte) []byte {
	padded := make([]byte, 4096)
	copy(padded, src)
	return padded
}
