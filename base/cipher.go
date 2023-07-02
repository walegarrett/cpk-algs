package base

import (
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/nacl/secretbox"
)

type Cipher [32]byte

func (c *Cipher) Cipher(message []byte) (out []byte) {
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		panic(err)
	}
	out = make([]byte, 0)
	out = append(out, nonce[:]...)
	key := [32]byte(*c)
	out = secretbox.Seal(out, message, &nonce, &key)
	return
}

func (c *Cipher) Decipher(secret []byte) (message []byte, err error) {
	if len(secret) < 24 {
		return nil, errors.New("cipher: too small secret")
	}
	message = make([]byte, 0)
	var nonce [24]byte
	copy(nonce[:], secret[:24])
	key := [32]byte(*c)
	message, ok := secretbox.Open(message, secret[24:], &nonce, &key)
	if !ok {
		return nil, errors.New("cipher: verification failed")
	}
	return
}
