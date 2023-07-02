package base

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

func PasswordEncrypt(password string) (string, error) {
	var salt [32]byte
	_, err := rand.Read(salt[:])
	if err != nil {
		return "", err
	}
	h := hmac.New(sha256.New, salt[:])
	h.Write([]byte(password))
	return hex.EncodeToString(salt[:]) + ":" + hex.EncodeToString(h.Sum(nil)), nil
}

func PasswordVerify(record string, password string) (err error) {
	splits := strings.Split(strings.TrimSpace(record), ":")
	if splits == nil || len(splits) != 2 {
		return errors.New("pwd: record illegal")
	}
	salt, err := hex.DecodeString(splits[0])
	if err != nil {
		return
	}
	toCmp := splits[1]
	h := hmac.New(sha256.New, salt)
	h.Write([]byte(password))
	if toCmp != hex.EncodeToString(h.Sum(nil)) {
		return errors.New("pwd: not correct")
	}
	return nil
}
