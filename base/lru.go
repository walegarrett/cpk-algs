package base

import (
	"cpk-algs/logger"
)

type Element struct {
	pre   *Element
	next  *Element
	key   string
	value interface{}
}

func NewElement(key string, value interface{}) *Element {
	var element Element
	element.key = key
	element.value = value
	element.pre = new(Element)
	element.next = new(Element)
	return &element
}

type LRU struct {
	capacity int64
	cache    map[string]*Element
	// virtual head node
	head *Element
	// virtual tail node
	tail    *Element
	queries func(key string) interface{}
}

func NewLRU(cnt int64, queries func(string) interface{}) *LRU {
	var lru LRU
	lru.capacity = cnt
	lru.cache = make(map[string]*Element, cnt)
	lru.head = new(Element)
	lru.tail = new(Element)
	lru.head.pre = lru.tail
	lru.head.next = lru.tail
	lru.tail.pre = lru.head
	lru.tail.next = lru.head
	lru.queries = queries
	return &lru
}

func (lru *LRU) removeNode(ele *Element) {
	ele.pre.next = ele.next
	ele.next.pre = ele.pre
}

func (lru *LRU) removeHead() *Element {
	ele := lru.head.next
	lru.removeNode(ele)
	return ele
}

func (lru *LRU) addToTail(ele *Element) {
	lru.tail.pre.next = ele
	ele.pre = lru.tail.pre
	ele.next = lru.tail
	lru.tail.pre = ele
}

func (lru *LRU) removeToTail(ele *Element) {
	lru.removeNode(ele)
	lru.addToTail(ele)
}

func (lru *LRU) removeOldest() {
	head := lru.removeHead()
	delete(lru.cache, head.key)
}

func (lru *LRU) Query(key string) interface{} {
	node, ok := lru.cache[key]
	if !ok {
		// key not exist
		logger.Logger.Info("miss the cache, key", key)
		//fmt.Printf("miss the cache, key: %+v\n", key)
		if int64(len(lru.cache)) >= lru.capacity {
			lru.removeOldest()
		}
		value := lru.queries(key)
		element := NewElement(key, value)
		lru.addToTail(element)
		lru.cache[key] = element
		return value
	} else {
		// key exist
		logger.Logger.Info("hit the cache, key", node.key, "value", node.value)
		//fmt.Printf("hit the cache, key:%+v, value:%+v\n", node.key, node.value)
		lru.removeToTail(node)
		return node.value
	}
}
