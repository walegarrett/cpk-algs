package base

import (
	"cpk-algs/base/edwards25519"
	"crypto/rand"
	"testing"
)

func TestSerializer_WriteSerializable(t *testing.T) {
	var serializer Serializer
	var randomBytes [64]byte
	_, err := rand.Read(randomBytes[:])
	if err != nil {
		panic(err)
	}
	randomScalar := (&edwards25519.Scalar{}).SetUniformBytes(randomBytes[:])
	var randomPriv Ed25519Scala
	randomPriv.Scalar = randomScalar
	serializer.WriteSerializable(&randomPriv)

	randomPoint := (&edwards25519.Point{}).ScalarBaseMult(randomScalar)
	var randomPub Ed25519Point
	randomPub.Point = randomPoint
	serializer.WriteSerializable(&randomPub)

	deserializer, err := NewDeserializer(serializer)
	if err != nil {
		t.Error(err)
		return
	}

	var randomPriv2 Ed25519Scala
	_, err = deserializer.ReadSerializable(&randomPriv2)
	if err != nil {
		return
	}
	if randomScalar.Equal(randomPriv2.Scalar) != 1 {
		t.Error("bad deserializer scala:{}", randomPriv2.Scalar)
		return
	}

	var randomPub2 Ed25519Point
	_, err = deserializer.ReadSerializable(&randomPub2)
	if err != nil {
		return
	}
	if randomPub.Equal(randomPub2.Point) != 1 {
		t.Error("bad deserializer point:{}", randomPub2.Point)
		return
	}
}
