package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

var ServerPepper []byte

func init() {
	ServerPepper = make([]byte, 32)
	_, err := rand.Read(ServerPepper)
	if err != nil {
		panic("CRITICAL: Salt generation failed")
	}
}

func BlindHardwareID(clientUUID string) string {
	hasher := sha256.New()
	hasher.Write([]byte(clientUUID))
	hasher.Write(ServerPepper)
	return hex.EncodeToString(hasher.Sum(nil))
}

func VerifyPoW(challenge string, nonce string, difficulty int) bool {
	hash := sha256.Sum256([]byte(challenge + nonce))
	hashStr := hex.EncodeToString(hash[:])
	for i := 0; i < difficulty; i++ {
		if hashStr[i] != '0' {
			return false
		}
	}
	return true
}

func GenerateChallenge() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}