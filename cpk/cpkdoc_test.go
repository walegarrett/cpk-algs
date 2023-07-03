package cpk

import (
	"cpk-algs/base"
	"cpk-algs/base/edwards25519"
	"crypto/rand"
	"testing"
)

func TestSKPiece_Serialize(t *testing.T) {
	var serializer base.Serializer
	var randomBytes [64]byte
	_, err := rand.Read(randomBytes[:])
	if err != nil {
		panic(err)
	}
	randomScalar := (&edwards25519.Scalar{}).SetUniformBytes(randomBytes[:])
	var scala base.Ed25519Scala
	scala.Scalar = randomScalar
	var skPiece SKPiece
	skPiece.Index = 1
	skPiece.Secret = scala
	skPiece.Serialize(&serializer)

	deserializer, err := base.NewDeserializer(serializer)
	if err != nil {
		t.Error(err)
		return
	}

	var skPiece2 SKPiece
	err = skPiece2.DeSerialize(deserializer)
	if err != nil {
		t.Error(err)
		return
	}
	if randomScalar.Equal(skPiece2.Secret.Scalar) != 1 {
		t.Error("bad deserializer scala:{}", skPiece2.Secret.Scalar)
		return
	}
}

func TestPMPiece_Serialize(t *testing.T) {
	var serializer base.Serializer
	var randomBytes [64]byte
	_, err := rand.Read(randomBytes[:])
	if err != nil {
		panic(err)
	}
	randomScalar := (&edwards25519.Scalar{}).SetUniformBytes(randomBytes[:])
	randomPoint := (&edwards25519.Point{}).ScalarBaseMult(randomScalar)
	var point base.Ed25519Point
	point.Point = randomPoint
	var pmPiece PMPiece
	pmPiece.Piece = []base.Ed25519Point{point}
	pmPiece.Serialize(&serializer)

	deserializer, err := base.NewDeserializer(serializer)
	if err != nil {
		t.Error(err)
		return
	}
	var pmPiece2 PMPiece
	err = pmPiece2.DeSerialize(deserializer)
	if err != nil {
		t.Error(err)
		return
	}
	if point.Equal(pmPiece2.Piece[0].Point) != 1 {
		t.Error("bad deserializer point:{}", pmPiece2.Piece[0].Point)
		return
	}
}
