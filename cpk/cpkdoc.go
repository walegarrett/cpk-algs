package cpk

import (
	"bytes"
	"encoding/binary"
	"github.com/walegarrett/cpk-algs/base"
	"github.com/walegarrett/cpk-algs/base/edwards25519"
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
	var l int64
	_, err = deserializer.ReadInt64(&l)
	if err != nil {
		return err
	}
	pmPiece.Piece = make([]base.Ed25519Point, l)
	for i := int64(0); i < l; i++ {
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
	// 矩阵分片数量（两个分片组成一个完整的矩阵）
	piecesCount = 4
	// 每个分片矩阵的元素数量
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

func (client *Client) QueryPublicKeyMatrix() []base.Ed25519Point {
	return client.publicMatrix
}

func (client *Client) Serialize(serializer *base.Serializer) {
	serializer.WriteInt64(int64(len(client.publicMatrix)))
	for _, ed25519Point := range client.publicMatrix {
		serializer.WriteSerializable(&ed25519Point)
	}
}

func (client *Client) Deserialize(deserializer *base.DeSerializer) error {
	var l int64
	_, err := deserializer.ReadInt64(&l)
	if err != nil {
		return err
	}
	client.publicMatrix = make([]base.Ed25519Point, l)
	for i := int64(0); i < l; i++ {
		_, err = deserializer.ReadSerializable(&(client.publicMatrix[i]))
		if err != nil {
			return err
		}
	}
	client.initQueries()
	return nil
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
// 0 + 2 = sk
// 1 + 3 = sk
func (client *Client) CombineSKPieces(skPieces []SKPiece, myPublicKey base.PublicKey) (bool, base.PrivateKey) {
	candidates := [2]base.Ed25519Scala{}
	for i := 0; i < 2; i++ {
		candidates[i] = *base.NewEd25519Scala()
	}
	set := make(map[int]void)
	// 组合出分片列表中的候选组合
	for index, skPiece := range skPieces {
		if _, exist := set[index]; !exist {
			set[index] = void{}
			candidates[skPiece.Index&1].Scalar.Add(candidates[skPiece.Index&1].Scalar, skPiece.Secret.Scalar)
		}
	}
	// 遍历每个候选的私钥组合，找到与公钥对应的私钥组合
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

// CombinePMPieces combine the public matrix
func (client *Client) CombinePMPieces(pmPieces []PMPiece) {
	cnt := [2]int{0, 0}
	m := make(map[int]PMPiece)
	for _, pmPiece := range pmPieces {
		if _, exist := m[int(pmPiece.Index)]; !exist {
			m[int(pmPiece.Index)] = pmPiece
			cnt[pmPiece.Index&1]++
		}
	}
	// 校验是否能组成两个子矩阵
	if cnt[0] != piecesCount/2 || cnt[0] != cnt[1] {
		panic("public matrix pieces not enough")
	}

	client.publicMatrix = nil
	for i := 0; i < 2; i++ {
		// 遍历每种组合
		for j := i; j < piecesCount; j += 2 {
			// 将0,2或者1,3这两种组合组成完整的矩阵
			k := 0
			for _, point := range m[j].Piece {
				if i == 0 {
					// 取0,2这种组合
					client.publicMatrix = append(client.publicMatrix, point)
				} else {
					// 校验前一轮的point与当前组合的同一个位置的point是否相同
					prePoint := client.publicMatrix[matrixPieceSize*(j/2)+k].Point
					if prePoint.Equal(point.Point) != 1 {
						panic("not consistent")
					}
				}
				k++
			}
		}
	}
	client.initQueries()
}

func (client *Client) CreatePublicKeyMatrixFromPrivateKeyMatrix(privateKeyMatrix []base.Ed25519Scala) {
	client.publicMatrix = nil
	for _, ed25519Scala := range privateKeyMatrix {
		ed25519Point := base.Ed25519Point{}
		ed25519Point.Point = (&edwards25519.Point{}).ScalarBaseMult(ed25519Scala.Scalar)
		client.publicMatrix = append(client.publicMatrix, ed25519Point)
	}
	client.initQueries()
}

type CA struct {
	privateMatrix []base.Ed25519Scala
}

func (ca *CA) InitCA(genKey string) {
	counter := int64(0)
	for i := 0; i < matrixSize; i++ {
		hash, err := blake2b.New512([]byte(genKey))
		if err != nil {
			panic(err)
		}
		bytesBuffer := bytes.NewBuffer([]byte{})
		err = binary.Write(bytesBuffer, binary.LittleEndian, counter)
		if err != nil {
			panic(err)
		}
		hash.Write(bytesBuffer.Bytes())

		ca.privateMatrix = append(ca.privateMatrix, *(base.FromHashToScala(hash)))
		counter++
	}
}

// QuerySK query the user's private key
func (ca *CA) QuerySK(ident string) base.PrivateKey {
	sum := base.NewEd25519Scala()
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
			sum.Scalar.Add(sum.Scalar, ca.privateMatrix[matrixRows*y+x].Scalar)
		}
	}
	var privateKey base.PrivateKey
	privateKey.Scalar = sum.Scalar
	return privateKey
}

func (ca *CA) ExportPublicMatrixForClient(client *Client) {
	client.CreatePublicKeyMatrixFromPrivateKeyMatrix(ca.privateMatrix)
}

func (ca *CA) Serialize(serializer *base.Serializer) {
	serializer.WriteInt64(int64(len(ca.privateMatrix)))
	for _, ed25519Point := range ca.privateMatrix {
		serializer.WriteSerializable(&ed25519Point)
	}
}

func (ca *CA) Deserialize(deserializer *base.DeSerializer) error {
	var l int64
	_, err := deserializer.ReadInt64(&l)
	if err != nil {
		return err
	}
	ca.privateMatrix = make([]base.Ed25519Scala, l)
	for i := int64(0); i < l; i++ {
		_, err = deserializer.ReadSerializable(&(ca.privateMatrix[i]))
		if err != nil {
			return err
		}
	}
	return nil
}

type DistributedCA struct {
	privateMatrixPiece []base.Ed25519Scala
	Index              int64
}

func (distributedCA *DistributedCA) InitDistributedCA(index int64, genKey string) {
	counter := int64(0)
	if index >= 2 {
		counter += matrixPieceSize
	}
	for i := 0; i < matrixPieceSize; i++ {
		hash, err := blake2b.New512([]byte(genKey))
		if err != nil {
			panic(err)
		}
		bytesBuffer := bytes.NewBuffer([]byte{})
		err = binary.Write(bytesBuffer, binary.LittleEndian, counter)
		if err != nil {
			panic(err)
		}
		hash.Write(bytesBuffer.Bytes())

		distributedCA.privateMatrixPiece = append(distributedCA.privateMatrixPiece, *(base.FromHashToScala(hash)))
		counter++
	}
	distributedCA.Index = index
}

// QuerySK returns the private key piece
func (distributedCA *DistributedCA) QuerySK(ident string) SKPiece {
	sum := base.NewEd25519Scala()
	hash, err := blake2b.New512(nil)
	if err != nil {
		panic(err)
	}
	hash.Write([]byte(ident))
	hs := base.FromHash(hash)
	if distributedCA.Index >= 2 {
		// 对于序号为2,3的节点需要跳过前一个节点占用的元素数量（0,2组成完整的矩阵，1,3也组成完整的矩阵）
		for i := 0; i < (matrixRows/subsSize/piecesCount*2)*(2+subsSize); i++ {
			hs.ToNextByte()
		}
	}
	for i := 0; i < matrixRows/subsSize/piecesCount*2; i++ {
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
			sum.Scalar.Add(sum.Scalar, distributedCA.privateMatrixPiece[matrixRows*y+x].Scalar)
		}
	}
	var skPiece SKPiece
	skPiece.Index = distributedCA.Index
	skPiece.Secret = *sum
	return skPiece
}

func (distributedCA *DistributedCA) ExportPublicMatrixPiece() PMPiece {
	pmPiece := PMPiece{}
	for _, ed25519Scala := range distributedCA.privateMatrixPiece {
		ed25519Point := base.Ed25519Point{}
		ed25519Point.Point = (&edwards25519.Point{}).ScalarBaseMult(ed25519Scala.Scalar)
		pmPiece.Piece = append(pmPiece.Piece, ed25519Point)
	}
	pmPiece.Index = distributedCA.Index
	return pmPiece
}

func (distributedCA *DistributedCA) Serialize(serializer *base.Serializer) {
	serializer.WriteInt64(int64(len(distributedCA.privateMatrixPiece)))
	for _, ed25519Point := range distributedCA.privateMatrixPiece {
		serializer.WriteSerializable(&ed25519Point)
	}
	serializer.WriteInt64(distributedCA.Index)
}

func (distributedCA *DistributedCA) Deserialize(deserializer *base.DeSerializer) error {
	var l int64
	_, err := deserializer.ReadInt64(&l)
	if err != nil {
		return err
	}
	distributedCA.privateMatrixPiece = make([]base.Ed25519Scala, l)
	for i := int64(0); i < l; i++ {
		_, err = deserializer.ReadSerializable(&(distributedCA.privateMatrixPiece[i]))
		if err != nil {
			return err
		}
	}
	_, err = deserializer.ReadInt64(&(distributedCA.Index))
	if err != nil {
		return err
	}
	return nil
}
