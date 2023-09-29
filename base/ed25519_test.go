package base

import (
	"crypto/rand"
	"github.com/walegarrett/cpk-algs/base/edwards25519"
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

func TestEd25519Point_add(t *testing.T) {
	ed25519Point := NewEd25519Point()
	var randomBytes [64]byte
	_, err := rand.Read(randomBytes[:])
	if err != nil {
		panic(err)
	}
	scalar1 := (&edwards25519.Scalar{}).SetUniformBytes(randomBytes[:])
	var ed25519Scala1 Ed25519Scala
	ed25519Scala1.Scalar = scalar1
	ed25519Point.Point.Add(ed25519Point.Point, (&edwards25519.Point{}).ScalarBaseMult(ed25519Scala1.Scalar))

	_, err = rand.Read(randomBytes[:])
	if err != nil {
		panic(err)
	}
	scalar2 := (&edwards25519.Scalar{}).SetUniformBytes(randomBytes[:])
	var ed25519Scala2 Ed25519Scala
	ed25519Scala2.Scalar = scalar2
	ed25519Point.Point.Add(ed25519Point.Point, (&edwards25519.Point{}).ScalarBaseMult(ed25519Scala2.Scalar))

	var ed25519Scala = NewEd25519Scala()
	ed25519Scala.Scalar.Add(ed25519Scala.Scalar, ed25519Scala1.Scalar)
	ed25519Scala.Scalar.Add(ed25519Scala.Scalar, ed25519Scala2.Scalar)

	if (&edwards25519.Point{}).ScalarBaseMult(ed25519Scala.Scalar).Equal(ed25519Point.Point) != 1 {
		t.Error("point add error")
		return
	}
}
