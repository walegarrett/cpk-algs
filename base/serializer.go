package base

import (
	"encoding/binary"
	"errors"
)

type Serializer []byte

func (s *Serializer) WriteBytes(val []byte) *Serializer {
	if s == nil || *s == nil {
		*s = []byte{}
	}
	*s = append(*s, val...)
	return s
}

func (s *Serializer) WriteInt64(val int64) *Serializer {
	var buf = make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(val))
	s.WriteBytes(buf)
	return s
}

func (s *Serializer) WriteInt32(val int32) *Serializer {
	var buf = make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(val))
	s.WriteBytes(buf)
	return s
}

func (s *Serializer) WriteString(val string) *Serializer {
	s.WriteInt64(int64(len(val)))
	s.WriteBytes([]byte(val))
	return s
}

type DeSerializer struct {
	buf   []byte
	cur   uint64
	total uint64
}

func NewDeserializer(src []byte) (*DeSerializer, error) {
	if src == nil {
		return nil, errors.New("empty src slice byte")
	}
	d := DeSerializer{}
	d.buf = make([]byte, len(src))
	copy(d.buf, src)
	d.cur = 0
	d.total = uint64(len(src))
	return &d, nil
}

func (d *DeSerializer) ReadBytes(data []byte, len uint64) (*DeSerializer, error) {
	if d.cur+len > d.total {
		return nil, errors.New("deserializer stream eof")
	}
	for i := 0; uint64(i) < len; i++ {
		data[i] = d.buf[d.cur+uint64(i)]
	}
	d.cur += len
	return d, nil
}

func (d *DeSerializer) ReadInt64(data *int64) (*DeSerializer, error) {
	buf := make([]byte, 8)
	_, err := d.ReadBytes(buf, 8)
	if err != nil {
		return nil, err
	}
	val := int64(binary.BigEndian.Uint64(buf))
	*data = val
	return d, nil
}

func (d *DeSerializer) ReadInt32(data *int32) (*DeSerializer, error) {
	buf := make([]byte, 4)
	_, err := d.ReadBytes(buf, 4)
	if err != nil {
		return nil, err
	}
	val := int32(binary.BigEndian.Uint32(buf))
	*data = val
	return d, nil
}

func (d *DeSerializer) ReadString(data *string) (*DeSerializer, error) {
	var len int64
	_, err := d.ReadInt64(&len)
	if err != nil {
		return nil, err
	}
	var buf = make([]byte, len)
	_, err = d.ReadBytes(buf, uint64(len))
	if err != nil {
		return nil, err
	}
	s := string(buf[:])
	*data = s
	return d, nil
}
