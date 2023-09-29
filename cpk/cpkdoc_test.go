package cpk

import (
	"crypto/rand"
	"github.com/walegarrett/cpk-algs/base"
	"github.com/walegarrett/cpk-algs/base/edwards25519"
	"strconv"
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

func TestDistributedCA_Deserialize(t *testing.T) {
	var distributedCAs [piecesCount]DistributedCA
	genKeys := []string{"gen_key1", "gen_key2"}
	for i := 0; i < piecesCount; i++ {
		// 0,1  2,3分别使用一个不同的key用于生成分片私钥矩阵
		idx := 0
		if i >= 2 {
			idx = 1
		}
		distributedCAs[i].InitDistributedCA(int64(i), genKeys[idx])

		var serializer base.Serializer
		distributedCAs[i].Serialize(&serializer)
		deserializer, err := base.NewDeserializer(serializer)
		if err != nil {
			t.Error(err)
			return
		}
		var distributedCA DistributedCA
		err = distributedCA.Deserialize(deserializer)
		if err != nil {
			t.Error(err)
			return
		}
		if i != (int)(distributedCA.Index) {
			t.Error("bad serializer index:{}", distributedCA.Index)
			return
		}
		if matrixPieceSize != len(distributedCA.privateMatrixPiece) {
			t.Error("bad serialzer private matrix piece:{}", distributedCA.privateMatrixPiece)
			return
		}
	}
}
func TestClient_CombineSKPieces(t *testing.T) {
	var distributedCAs [piecesCount]DistributedCA
	genKeys := []string{"gen_key1", "gen_key2"}
	var pmPieces []PMPiece
	for i := 0; i < piecesCount; i++ {
		// 0,1  2,3分别使用一个不同的key用于生成分片私钥矩阵
		idx := 0
		if i >= 2 {
			idx = 1
		}
		distributedCAs[i].InitDistributedCA(int64(i), genKeys[idx])
		pmPieces = append(pmPieces, distributedCAs[i].ExportPublicMatrixPiece())
	}
	client := Client{}
	client.CombinePMPieces(pmPieces)

	count := 8
	for count > 0 {
		var skPieces []SKPiece
		ident := "ident" + strconv.Itoa(count)
		publicKey := client.QueryPK(ident)
		for j := 0; j < piecesCount; j++ {
			skPieces = append(skPieces, distributedCAs[j].QuerySK(ident))
		}
		res, privateKey := client.CombineSKPieces(skPieces, *publicKey)
		if !res {
			t.Error("combine private key pieces failed")
			return
		}
		if publicKey.Point.Equal((&edwards25519.Point{}).ScalarBaseMult(privateKey.Scalar)) != 1 {
			t.Error("combined private key is not corresponding to public key")
			return
		}
		count--
	}

	count = 8
	for count > 0 {
		var skPieces []SKPiece
		ident := "ident" + strconv.Itoa(count)
		publicKey := client.QueryPK(ident)
		// ban用于测试某个切片丢失的情况
		ban := count & 4
		for j := 0; j < piecesCount; j++ {
			if j == ban {
				continue
			}
			skPieces = append(skPieces, distributedCAs[j].QuerySK(ident))
		}
		res, privateKey := client.CombineSKPieces(skPieces, *publicKey)
		if !res {
			t.Error("combine private key pieces failed")
			return
		}
		if publicKey.Point.Equal((&edwards25519.Point{}).ScalarBaseMult(privateKey.Scalar)) != 1 {
			t.Error("combined private key is not corresponding to public key")
			return
		}
		count--
	}
}
