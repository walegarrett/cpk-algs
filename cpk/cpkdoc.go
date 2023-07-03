package cpk

import "cpk-algs/base"

// SKPiece defines a private key Piece
type SKPiece struct {
	// Index of sk Piece
	Index int64
	// Secret
	Secret base.Ed25519Scala
}

func (skPiece *SKPiece) Serialize(serializer *base.Serializer) {
	serializer.WriteInt64(skPiece.Index)
	serializer.WriteSerializable(&(skPiece.Secret))
}

func (skPiece *SKPiece) DeSerialize(deserializer *base.DeSerializer) error {
	_, err := deserializer.ReadInt64(&(skPiece.Index))
	if err != nil {
		return err
	}
	_, err = deserializer.ReadSerializable(&(skPiece.Secret))
	if err != nil {
		return err
	}
	return nil
}

// PMPiece defines a public matrix Piece
type PMPiece struct {
	// Index of public matrix Piece
	Index int64
	// Piece of public matrix
	Piece []base.Ed25519Point
}

func (pmPiece *PMPiece) Serialize(serializer *base.Serializer) {
	serializer.WriteInt64(pmPiece.Index)
	serializer.WriteInt64(int64(len(pmPiece.Piece)))
	for index := range pmPiece.Piece {
		serializer.WriteSerializable(&pmPiece.Piece[index])
	}
}

func (pmPiece *PMPiece) DeSerialize(deserializer *base.DeSerializer) error {
	_, err := deserializer.ReadInt64(&(pmPiece.Index))
	if err != nil {
		return err
	}
	var len int64
	_, err = deserializer.ReadInt64(&len)
	if err != nil {
		return err
	}
	pmPiece.Piece = make([]base.Ed25519Point, len)
	for i := int64(0); i < len; i++ {
		_, err = deserializer.ReadSerializable(&(pmPiece.Piece[i]))
		if err != nil {
			return err
		}
	}
	return nil
}
