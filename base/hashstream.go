package base

import (
	"bytes"
	"encoding/binary"
	"golang.org/x/crypto/blake2b"
	"hash"
)

const BytesMax = blake2b.Size

// Hashstream represents the unlimited hash str
type Hashstream struct {
	secret  []byte
	counter int64
	ptr     int64
	curr    []byte
}

func NewHashstream(src []byte) *Hashstream {
	if len(src) != BytesMax {
		panic("src's length cannot less than BytesMax")
		return nil
	}
	var hashstream Hashstream
	hashstream.counter = 0
	hashstream.ptr = BytesMax
	hashstream.secret = make([]byte, BytesMax)
	copy(hashstream.secret, src)
	hashstream.curr = make([]byte, BytesMax)
	return &hashstream
}

func (hashstrem *Hashstream) ToNextByte() byte {
	if hashstrem.ptr == BytesMax {
		hash, err := blake2b.New512(hashstrem.secret)
		if err != nil {
			panic(err)
		}
		hash.Write(hashstrem.secret)
		bytesBuffer := bytes.NewBuffer([]byte{})
		err = binary.Write(bytesBuffer, binary.LittleEndian, hashstrem.counter)
		if err != nil {
			panic(err)
		}
		hash.Write(bytesBuffer.Bytes())
		sum := hash.Sum(nil)
		copy(hashstrem.curr, sum[:])
		hashstrem.counter++
		hashstrem.ptr = 0
	}
	b := hashstrem.curr[hashstrem.ptr]
	hashstrem.ptr++
	return b
}

func FromHash(hash hash.Hash) *Hashstream {
	hashstream := NewHashstream(hash.Sum(nil))
	return hashstream
}
