package base

import (
	"bytes"
	"testing"
)

func Test_hash(t *testing.T) {
	hasher := NewHasher(nil)
	if hasher == nil {
		t.Error()
		return
	}
	bytes1 := hasher.Hash(32).Hash(true).Sum()
	if len(bytes1) != 64 {
		t.Error()
		return
	}
	hasher.Reset()
	bytes2 := hasher.Hash(32).Hash(true).Sum()
	if !bytes.Equal(bytes1, bytes2) {
		t.Error()
		return
	}
	hasher.Reset()
	bytes3 := hasher.Hash(32).Hash("").Hash(true).Sum()
	if !bytes.Equal(bytes1, bytes3) {
		t.Error()
		return
	}
}
