package base

import (
	"bytes"
	"encoding/hex"
	"github.com/walegarrett/cpk-algs/base/edwards25519"
	"testing"
)

func TestKxSign(t *testing.T) {
	priv := RandomPrivateKey()
	t.Log(hex.EncodeToString(priv.Scalar.Bytes()))
	pub := priv.Public()
	sig := priv.Sign([]byte("123456"))
	t.Log(hex.EncodeToString(sig.Bytes()))
	ok := pub.Verify([]byte("123456"), sig)
	if !ok {
		t.Error("verify failed")
		return
	}
	sent, key, err := pub.KxSend()
	if err != nil {
		t.Error(err)
		return
	}
	key2, err := priv.KxReceive(sent)
	if err != nil {
		t.Error(err)
		return
	}
	if !bytes.Equal(key[:], key2[:]) {
		t.Error("verify failed")
		return
	}
	t.Log(hex.EncodeToString(sent[:]))
	t.Log(hex.EncodeToString(key[:]))
	privBuf, err := hex.DecodeString("5399cfa5eab9bd2e54f1e57731b13a2c89aee7acc552f50377c9e291fcb5870d")
	if err != nil {
		t.Error(err)
		return
	}
	priv2 := new(PrivateKey)
	priv2.Scalar, err = (&edwards25519.Scalar{}).SetCanonicalBytes(privBuf)
	if err != nil {
		t.Error(err)
		return
	}
	decoded, err := hex.DecodeString("e618254b8cc4fe9abf995c8423e4657ad587a80932330faae4ac226ac97cb9d5")
	if err != nil {
		t.Error(err)
		return
	}
	key3, err := priv2.KxReceive(decoded)
	if err != nil {
		t.Error(err)
		return
	}
	if hex.EncodeToString(key3[:]) != "f0500705de23d877bc6b332514659a6d94e3e7835eaca4b471eea6541223b536cd42abcab96d409ef3a6bfb203e9051f2354457d81a781440c77688200ec60f8" {
		t.Error("not equal")
	}
}
