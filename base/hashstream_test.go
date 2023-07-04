package base

import (
	"encoding/hex"
	"testing"
)

func TestHashstream_ToNextByte(t *testing.T) {
	secret, err := hex.DecodeString("f0500705de23d877bc6b332514659a6d94e3e7835eaca4b471eea6541223b536cd42abcab96d409ef3a6bfb203e9051f2354457d81a781440c77688200ec60f8")
	if err != nil {
		t.Error(err)
		return
	}
	hashstream := NewHashstream(secret)
	byte := hashstream.ToNextByte()
	if byte != 130 {
		t.Error("hashstream to next byte error")
		return
	}
}
