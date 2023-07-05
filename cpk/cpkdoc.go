package cpk

import (
	"cpk-algs/base"
	"cpk-algs/base/edwards25519"
	"golang.org/x/crypto/blake2b"
)

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

const (
	// 公钥矩阵行数
	matrixRows = 32
	// 公钥矩阵元素数量
	matrixSize = matrixRows * matrixRows
	subsSize   = 8
	// 矩阵分片数量
	piecesCount = 4
	// 分片矩阵的元素数量
	matrixPieceSize = matrixSize / piecesCount * 2
)

var subsTable = [8][8]int{
	{
		0, 1, 2, 3, 4, 5, 6, 7,
	},
	{
		1, 2, 3, 4, 5, 6, 7, 0,
	},
	{
		2, 3, 4, 5, 6, 7, 0, 1,
	},
	{
		3, 4, 5, 6, 7, 0, 1, 2,
	},
	{
		4, 5, 6, 7, 0, 1, 2, 3,
	},
	{
		5, 6, 7, 0, 1, 2, 3, 4,
	},
	{
		6, 7, 0, 1, 2, 3, 4, 5,
	},
	{
		7, 0, 1, 2, 3, 4, 5, 6,
	},
}

type Client struct {
	publicMatrix  []base.Ed25519Point
	pkQueriesFunc func(key string) interface{}
}

// initQueries init the public key query func
func (client *Client) initQueries() {
	client.pkQueriesFunc = func(ident string) interface{} {
		sum := base.NewEd25519Point()
		hash, err := blake2b.New512(nil)
		if err != nil {
			panic(err)
		}
		hash.Write([]byte(ident))
		hs := base.FromHash(hash)
		for i := 0; i < matrixRows/subsSize; i++ {
			// 遍历每一个子矩阵
			// pi和pj用于从从subs_table中选出本次子矩阵的开始行
			pi := int(hs.ToNextByte() & 7)
			pj := int(hs.ToNextByte() & 7)
			// 遍历子矩阵的每一行
			for j := 0; j < subsSize; j++ {
				// 在总矩阵中的行数
				y := subsTable[(pi+j)%8][pj] + 8*i
				// 在总矩阵中的列数
				x := int((hs.ToNextByte() & (matrixRows - 1)) % matrixRows)
				sum.Point.Add(sum.Point, client.publicMatrix[matrixRows*y+x].Point)
			}
		}
		var publicKey base.PublicKey
		publicKey.Point = sum.Point
		return publicKey
	}
}

func NewClient(publicMatrix []base.Ed25519Point) *Client {
	var client Client
	client.publicMatrix = make([]base.Ed25519Point, len(publicMatrix))
	copy(client.publicMatrix, publicMatrix)
	client.initQueries()
	return &client
}

func (client *Client) QueryPK(ident string) *base.PublicKey {
	res := client.pkQueriesFunc(ident)
	publicKey, ok := res.(base.PublicKey)
	if !ok {
		panic("query pk failed")
	}
	return &publicKey
}

type void struct{}

// CombineSKPieces combine the sk piece
func (client *Client) CombineSKPieces(skPieces []SKPiece, myPublicKey base.PublicKey) (bool, base.PrivateKey) {
	candidates := [2]base.Ed25519Scala{}
	for i := 0; i < 2; i++ {
		candidates[i] = *base.NewEd25519Scala()
	}
	set := make(map[int]void)
	for i, skPiece := range skPieces {
		if _, exist := set[i]; !exist {
			set[i] = void{}
			candidates[int(skPiece.Index)&i].Scalar.Add(candidates[skPiece.Index].Scalar, skPiece.Secret.Scalar)
		}
	}
	for _, candidate := range candidates {
		point := edwards25519.Point{}
		if point.ScalarBaseMult(candidate.Scalar).Equal(myPublicKey.Point) == 1 {
			priv := base.PrivateKey{}
			priv.Scalar = candidate.Scalar
			return true, priv
		}
	}
	priv := base.PrivateKey{}
	priv.Scalar = candidates[0].Scalar
	return false, priv
}

func (client *Client) CominePMPieces(pmPieces []PMPiece) {

}
