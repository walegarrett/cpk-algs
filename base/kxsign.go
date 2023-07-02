package base

import (
	"bytes"
	"cpk/base/edwards25519"
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/blake2b"
)

type PublicKey struct {
	*edwards25519.Point
}

type PrivateKey struct {
	*edwards25519.Scalar
	initialized bool
	signKey     [32]byte
	pk          PublicKey
}

func (p *PrivateKey) initialize() {
	if p.initialized {
		return
	}
	res := blake2b.Sum512(p.Scalar.Bytes())
	copy(p.signKey[:], res[:32])
	p.pk.Point = (&edwards25519.Point{}).ScalarBaseMult(p.Scalar)
}

type Signature struct {
	s, c *edwards25519.Scalar
}

func (s *Signature) Bytes() []byte {
	var buf bytes.Buffer
	buf.Write(s.s.Bytes())
	buf.Write(s.c.Bytes())
	return buf.Bytes()
}

func (s *Signature) SetBytes(x []byte) (err error) {
	if len(x) != 64 {
		return errors.New("bad signature length")
	}
	_, err = s.s.SetCanonicalBytes(x[:32])
	if err != nil {
		return
	}
	_, err = s.c.SetCanonicalBytes(x[32:])
	if err != nil {
		return
	}
	return
}

func RandomPrivateKey() (priv PrivateKey) {
	var buf [64]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		panic(err)
	}
	priv.Scalar = (&edwards25519.Scalar{}).SetUniformBytes(buf[:])
	if err != nil {
		panic(err)
	}
	return
}

func (p *PrivateKey) Public() (pub PublicKey) {
	p.initialize()
	return p.pk
}

func (p *PrivateKey) Sign(m []byte) (sig *Signature) {
	p.initialize()
	hash, err := blake2b.New512(nil)
	if err != nil {
		panic(err)
	}
	_, err = hash.Write(p.signKey[:])
	if err != nil {
		panic(err)
	}
	_, err = hash.Write(m)
	if err != nil {
		panic(err)
	}
	r := (&edwards25519.Scalar{}).SetUniformBytes(hash.Sum(nil))
	R := (&edwards25519.Point{}).ScalarBaseMult(r)
	hash, err = blake2b.New512(nil)
	if err != nil {
		panic(err)
	}
	_, err = hash.Write(R.Bytes())
	if err != nil {
		panic(err)
	}
	_, err = hash.Write(p.pk.Bytes())
	if err != nil {
		panic(err)
	}
	_, err = hash.Write(m)
	if err != nil {
		panic(err)
	}
	c := (&edwards25519.Scalar{}).SetUniformBytes(hash.Sum(nil))
	r.MultiplyAdd(c, p.Scalar, r)
	return &Signature{
		s: r,
		c: c,
	}
}

func (p *PublicKey) Verify(m []byte, sign *Signature) bool {
	R := (&edwards25519.Point{}).VarTimeDoubleScalarBaseMult(sign.c, (&edwards25519.Point{}).Negate(p.Point), sign.s)
	hash, err := blake2b.New512(nil)
	if err != nil {
		panic(err)
	}
	_, err = hash.Write(R.Bytes())
	if err != nil {
		panic(err)
	}
	_, err = hash.Write(p.Bytes())
	if err != nil {
		panic(err)
	}
	_, err = hash.Write(m)
	if err != nil {
		panic(err)
	}
	return sign.c.Equal((&edwards25519.Scalar{}).SetUniformBytes(hash.Sum(nil))) == 1
}

func (p *PublicKey) KxSend() (sent []byte, key [64]byte, err error) {
	if p.Equal(edwards25519.NewIdentityPoint()) == 1 {
		err = errors.New("kx: bad public key")
		return
	}
	r := RandomPrivateKey()
	sentPt := (&edwards25519.Point{}).ScalarBaseMult(r.Scalar)
	shared := (&edwards25519.Point{}).ScalarMult(r.Scalar, p.Point)
	key = blake2b.Sum512(shared.Bytes())
	sent = sentPt.Bytes()
	return
}

func (p *PrivateKey) KxReceive(received []byte) (key [64]byte, err error) {
	pt, err := (&edwards25519.Point{}).SetBytes(received)
	if err != nil {
		return
	}
	if pt.Equal(edwards25519.NewIdentityPoint()) == 1 {
		err = errors.New("kx: bad public key")
		return
	}
	pt.ScalarMult(p.Scalar, pt)
	key = blake2b.Sum512(pt.Bytes())
	return
}
