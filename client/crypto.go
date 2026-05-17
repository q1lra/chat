package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

func SolvePoW(challenge string, difficulty int) string {
	var nonceBytes = make([]byte, 16)
	for {
		_, _ = rand.Read(nonceBytes)
		nonce := hex.EncodeToString(nonceBytes)
		hash := sha256.Sum256([]byte(challenge + nonce))
		hashStr := hex.EncodeToString(hash[:])

		isMatch := true
		for i := 0; i < difficulty; i++ {
			if hashStr[i] != '0' {
				isMatch = false
				break
			}
		}
		if isMatch {
			return nonce
		}
	}
}

func DeriveKey(passphrase string) []byte {
	hash := sha256.Sum256([]byte(passphrase))
	return hash[:]
}

func EncryptMessage(plainText string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plainText), nil)
	return hex.EncodeToString(ciphertext), nil
}

func DecryptMessage(cipherTextHex string, key []byte) (string, error) {
	ciphertext, err := hex.DecodeString(cipherTextHex)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plainTextBytes, err := aesGCM.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return "", errors.New("decryption failed: invalid key or tampered data")
	}

	return string(plainTextBytes), nil
}
