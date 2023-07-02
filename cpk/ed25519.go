package cpk

import (
	"cpk-algs/base/edwards25519"
)

type Ed25519Scala struct {
	*edwards25519.Scalar
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

type Ed25519Point struct {
	*edwards25519.Point
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
