package main

import (
	"database/sql"
	"errors"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type DBManager struct {
	db *sql.DB
}

func InitDB(filepath string) (*DBManager, error) {
	db, err := sql.Open("sqlite", filepath)
	if err != nil {
		return nil, err
	}
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		computer_hash TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS channels (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		owner_id INTEGER NOT NULL,
		is_private INTEGER DEFAULT 0,
		history_enabled INTEGER DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS channel_members (
		user_id INTEGER,
		channel_id INTEGER,
		PRIMARY KEY (user_id, channel_id)
	);
	CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		channel_id INTEGER,
		sender_id INTEGER,
		payload TEXT,
		timestamp TEXT
	);`
	_, err = db.Exec(schema)
	if err != nil {
		return nil, err
	}
	return &DBManager{db: db}, nil
}

func (mgr *DBManager) RegisterUser(username, password, compHash string) error {
	var totalUsers int
	err := mgr.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&totalUsers)
	if err != nil {
		return err
	}
	if totalUsers >= 25 {
		return errors.New("global account limit reached")
	}

	var compUsers int
	err = mgr.db.QueryRow("SELECT COUNT(*) FROM users WHERE computer_hash = ?", compHash).Scan(&compUsers)
	if err != nil {
		return err
	}
	if compUsers >= 25 {
		return errors.New("hardware account limit reached")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = mgr.db.Exec("INSERT INTO users (username, password_hash, computer_hash) VALUES (?, ?, ?)", username, string(hashedPassword), compHash)
	return err
}

func (mgr *DBManager) AuthenticateUser(username, password string) (int, error) {
	var id int
	var hash string
	err := mgr.db.QueryRow("SELECT id, password_hash FROM users WHERE username = ?", username).Scan(&id, &hash)
	if err != nil {
		return 0, err
	}
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (mgr *DBManager) CreateChannel(name string, ownerID int, isPrivate int) error {
	var totalChannels int
	err := mgr.db.QueryRow("SELECT COUNT(*) FROM channels WHERE owner_id = ?", ownerID).Scan(&totalChannels)
	if err != nil {
		return err
	}
	if totalChannels >= 25 {
		return errors.New("channel limit reached for this account")
	}

	tx, err := mgr.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec("INSERT INTO channels (name, owner_id, is_private, history_enabled) VALUES (?, ?, ?, 0)", name, ownerID, isPrivate)
	if err != nil {
		return err
	}

	chanID, err := res.LastInsertId()
	if err != nil {
		return err
	}

	_, err = tx.Exec("INSERT INTO channel_members (user_id, channel_id) VALUES (?, ?)", ownerID, chanID)
	if err != nil {
		return err
	}

	return tx.Commit()
}
