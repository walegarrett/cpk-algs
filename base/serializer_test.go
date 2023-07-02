package base

import "testing"

func TestSerializer_WriteInt64(t *testing.T) {
	var serializer Serializer
	serializer.WriteInt64(23)
	deserializer, err := NewDeserializer(serializer)
	if err != nil {
		t.Error(err)
		return
	}
	var val int64
	_, err = deserializer.ReadInt64(&val)
	if err != nil {
		t.Error(err)
		return
	}
	if val != 23 {
		t.Error("bad deserializer val:{}", val)
		return
	}
}

func TestSerializer_WriteString(t *testing.T) {
	var serializer Serializer
	serializer.WriteString("123456")
	deserializer, err := NewDeserializer(serializer)
	if err != nil {
		t.Error(err)
		return
	}
	var val string
	_, err = deserializer.ReadString(&val)
	if err != nil {
		t.Error(err)
		return
	}
	if "123456" != val {
		t.Error("bad deserializer val:{}", val)
		return
	}
}

func TestSerializer_WriteInt32(t *testing.T) {
	var serializer Serializer
	serializer.WriteInt32(11111)
	serializer.WriteString("23456")
	deserializer, err := NewDeserializer(serializer)
	if err != nil {
		t.Error(err)
		return
	}
	var val int32
	_, err = deserializer.ReadInt32(&val)
	if err != nil {
		t.Error(err)
		return
	}
	if val != 11111 {
		t.Error("bad deserializer val:{}", val)
		return
	}
	var str string
	_, err = deserializer.ReadString(&str)
	if err != nil {
		t.Error(err)
		return
	}
	if str != "23456" {
		t.Error("bad deserializer str:{}", str)
		return
	}
}
