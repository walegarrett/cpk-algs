package base

import "testing"

func TestLRU_Query(t *testing.T) {
	var f = func(key string) interface{} {
		return key + "-value"
	}
	lru := NewLRU(3, f)
	value := lru.Query("123")
	if "123-value" != value {
		t.Error("lru query error")
		return
	}

	value = lru.Query("124")
	if "124-value" != value {
		t.Error("lru query error")
		return
	}

	value = lru.Query("123")
	if "123-value" != value {
		t.Error("lru query error")
		return
	}

	value = lru.Query("125")
	if "125-value" != value {
		t.Error("lru query error")
		return
	}

	value = lru.Query("124")
	if "124-value" != value {
		t.Error("lru query error")
		return
	}

	value = lru.Query("126")
	if "126-value" != value {
		t.Error("lru query error")
		return
	}

	value = lru.Query("123")
	if "123-value" != value {
		t.Error("lru query error")
		return
	}

}
