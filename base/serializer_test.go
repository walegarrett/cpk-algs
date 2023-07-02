package base

import (
	"cpk-algs/base/edwards25519"
	"cpk-algs/cpk"
	"crypto/rand"
	"testing"
)

func TestSerializer_WriteInt64(t *testing.T) {
	var serializer Serializer
	serializer.WriteInt64(23)
	deserializer, err := NewDeserializer(serializer)
	if err != nil {
		t.Error(err)
		return
	}
	var val int64
	_, err = deserializer.ReadInt64(&val)
	if err != nil {
		t.Error(err)
		return
	}
	if val != 23 {
		t.Error("bad deserializer val:{}", val)
		return
	}
}

func TestSerializer_WriteString(t *testing.T) {
	var serializer Serializer
	serializer.WriteString("123456")
	deserializer, err := NewDeserializer(serializer)
	if err != nil {
		t.Error(err)
		return
	}
	var val string
	_, err = deserializer.ReadString(&val)
	if err != nil {
		t.Error(err)
		return
	}
	if "123456" != val {
		t.Error("bad deserializer val:{}", val)
		return
	}
}

func TestSerializer_WriteInt32(t *testing.T) {
	var serializer Serializer
	serializer.WriteInt32(11111)
	serializer.WriteString("23456")
	deserializer, err := NewDeserializer(serializer)
	if err != nil {
		t.Error(err)
		return
	}
	var val int32
	_, err = deserializer.ReadInt32(&val)
	if err != nil {
		t.Error(err)
		return
	}
	if val != 11111 {
		t.Error("bad deserializer val:{}", val)
		return
	}
	var str string
	_, err = deserializer.ReadString(&str)
	if err != nil {
		t.Error(err)
		return
	}
	if str != "23456" {
		t.Error("bad deserializer str:{}", str)
		return
	}
}

func TestSerializer_WriteSerializable(t *testing.T) {
	var serializer Serializer
	var randomBytes [64]byte
	_, err := rand.Read(randomBytes[:])
	if err != nil {
		panic(err)
	}
	randomScalar := (&edwards25519.Scalar{}).SetUniformBytes(randomBytes[:])
	var randomPriv cpk.Ed25519Scala
	randomPriv.Scalar = randomScalar
	serializer.WriteSerializable(&randomPriv)

	randomPoint := (&edwards25519.Point{}).ScalarBaseMult(randomScalar)
	var randomPub cpk.Ed25519Point
	randomPub.Point = randomPoint
	serializer.WriteSerializable(&randomPub)

	deserializer, err := NewDeserializer(serializer)
	if err != nil {
		t.Error(err)
		return
	}

	var randomPriv2 cpk.Ed25519Scala
	_, err = deserializer.ReadSerializable(&randomPriv2)
	if err != nil {
		return
	}
	if randomScalar.Equal(randomPriv2.Scalar) != 1 {
		t.Error("bad deserializer scala:{}", randomPriv2.Scalar)
		return
	}

	var randomPub2 cpk.Ed25519Point
	_, err = deserializer.ReadSerializable(&randomPub2)
	if err != nil {
		return
	}
	if randomPub.Equal(randomPub2.Point) != 1 {
		t.Error("bad deserializer point:{}", randomPub2.Point)
		return
	}
}
