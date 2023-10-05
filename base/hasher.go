package base

import (
	"encoding/binary"
	"encoding/hex"
	"golang.org/x/crypto/blake2b"
	"hash"
)

const (
	// The hash size of BLAKE2b-512 in bytes.
	Size = 64
	// The hash size of BLAKE2b-384 in bytes.
	Size384 = 48
	// The hash size of BLAKE2b-256 in bytes.
	Size256 = 32
)

// Hasher 是哈希工具类的结构
type Hasher struct {
	hasher hash.Hash
}

// NewHasherWithByteSize 创建一个新的哈希工具类实例
func NewHasherWithByteSize(size int, key []byte) *Hasher {
	h, err := blake2b.New(size, key)
	if err != nil {
		return nil
	}
	return &Hasher{hasher: h}
}

// NewHasher 创建一个新的哈希工具类实例
func NewHasher(key []byte) *Hasher {
	h, err := blake2b.New512(key)
	if err != nil {
		return nil
	}
	return &Hasher{hasher: h}
}

// Hash 将任意数据类型的值哈希化，并返回哈希值的十六进制字符串表示
func (h *Hasher) Hash(value interface{}) *Hasher {
	switch value.(type) {
	case string:
		_, err := h.hasher.Write([]byte(value.(string)))
		if err != nil {
			return nil
		}
	case int:
		bytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(bytes, uint32(value.(int)))
		_, err := h.hasher.Write(bytes)
		if err != nil {
			return nil
		}
	case int32:
		bytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(bytes, uint32(value.(int32)))
		_, err := h.hasher.Write(bytes)
		if err != nil {
			return nil
		}
	case uint32:
		bytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(bytes, value.(uint32))
		_, err := h.hasher.Write(bytes)
		if err != nil {
			return nil
		}
	case int64:
		bytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(bytes, uint64(value.(int64)))
		_, err := h.hasher.Write(bytes)
		if err != nil {
			return nil
		}
	case uint64:
		bytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(bytes, value.(uint64))
		_, err := h.hasher.Write(bytes)
		if err != nil {
			return nil
		}
	case bool:
		var boolBytes byte = 0
		if value.(bool) {
			boolBytes = 1
		}
		_, err := h.hasher.Write([]byte{boolBytes})
		if err != nil {
			return nil
		}
	case []byte:
		_, err := h.hasher.Write(value.([]byte))
		if err != nil {
			return nil
		}
	default:
		return nil
	}
	return h
}

func (h *Hasher) Sum() []byte {
	return h.hasher.Sum(nil)
}

func (h *Hasher) SumStr() string {
	hashBytes := h.hasher.Sum(nil)
	return hex.EncodeToString(hashBytes)
}

func (h *Hasher) Reset() {
	h.hasher.Reset()
}
