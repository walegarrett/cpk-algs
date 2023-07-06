package base

import (
	"cpk-algs/base/edwards25519"
	"hash"
)

type Ed25519Scala struct {
	*edwards25519.Scalar
}

func NewEd25519Scala() *Ed25519Scala {
	var scala Ed25519Scala
	scala.Scalar = &edwards25519.Scalar{}
	return &scala
}

func (scala *Ed25519Scala) SerializedByteSize() int64 {
	return 32
}

func (scala *Ed25519Scala) Bytes() []byte {
	return scala.Scalar.Bytes()
}

func (scala *Ed25519Scala) SetBytes(bytes []byte) (err error) {
	sc, err := (&edwards25519.Scalar{}).SetCanonicalBytes(bytes)
	if err != nil {
		return
	}
	scala.Scalar = sc
	return nil
}

func FromHashToScala(hash hash.Hash) *Ed25519Scala {
	bytes := hash.Sum(nil)
	scala := Ed25519Scala{}
	scala.SetUniformBytes(bytes)
	return &scala
}

type Ed25519Point struct {
	*edwards25519.Point
}

func NewEd25519Point() *Ed25519Point {
	var point Ed25519Point
	point.Point = &(edwards25519.Point{})
	return &point
}

func (point *Ed25519Point) SerializedByteSize() int64 {
	return 32
}

func (point *Ed25519Point) Bytes() []byte {
	return point.Point.Bytes()
}

func (point *Ed25519Point) SetBytes(bytes []byte) (err error) {
	pt, err := (&edwards25519.Point{}).SetBytes(bytes)
	if err != nil {
		return
	}
	point.Point = pt
	return nil
}
