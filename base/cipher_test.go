package base

import (
	"encoding/hex"
	"testing"
)

func TestCipher(t *testing.T) {
	kx, err := hex.DecodeString("60f5d407f34bccbd1c4119a3182d0952e31ed850ee71b1cec59f6160cb0a6f1e0273b34cd6897a296b3ddb76023183406687ed47900fed8f970bdf2d2ad3d2e1")
	if err != nil {
		t.Error(err)
		return
	}
	var key Cipher
	copy(key[:], kx[:32])
	buf, err := key.Decipher(key.Cipher([]byte("12345")))
	if err != nil {
		t.Error(err)
		return
	}
	if "12345" != string(buf) {
		t.Error("bad cipher")
		return
	}
	box, err := hex.DecodeString("e53ad03ca79e19b41590559383dd55a081f4c5498059b148fa0b885f3eb9ee30bf3a4c555c339f3f4306d64189f71a8fc9a0871870e90f2c")
	if err != nil {
		t.Error(err)
		return
	}
	buf, err = key.Decipher(box)
	if err != nil {
		t.Error(err)
		return
	}
	if "1234567890123456" != string(buf) {
		t.Error("bad cipher")
		return
	}
}
