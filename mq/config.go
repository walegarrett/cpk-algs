package mq

import "cpk-authentication/base"

type Config struct {
	NodePort     uint16
	ClientPort   uint16
	PasswordHash string
	SKey         base.PrivateKey
}
