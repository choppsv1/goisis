package main

import (
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/tlv"
	"reflect"
	"unsafe"
)

type addr []byte

const (
	foo = iota + 3
	bar
	baz = iota + 8
	foobar
)

func playground() {
	var s string
	var tlvArray = []byte{1, 1, 0xff}
	var tlvData = tlv.Data(tlvArray[:])
	var tlvBData = []byte(tlvData)
	var void interface{}

	s = "ABCD\x31"
	void = s

	var ab = make([]byte, 6)
	var a addr = ab

	tlv.TLV.Type(tlvData)
	// tlv.TLV.Type(tlvArray)

	// fmt.Printf("%s\n", s)
	//void = reflect.ValueOf(s).Bytes()
	fmt.Printf("void value, type: %t\n", void)

	fmt.Printf("tlvArray type: %s\n", reflect.TypeOf(tlvArray).String())
	fmt.Printf("tlvData type: %s\n", reflect.TypeOf(tlvData).String())
	fmt.Printf("tlvBData type: %s\n", reflect.TypeOf(tlvBData).String())
	fmt.Printf("ab type: %s\n", reflect.TypeOf(ab).String())
	fmt.Printf("a type: %s\n", reflect.TypeOf(a).String())

	var ids *[]tlv.SystemID
	typ := reflect.TypeOf(ids)
	fmt.Printf("typ type: %s\n", typ.String())

	typ = typ.Elem()
	fmt.Printf("*typ type: %s\n", typ.String())

	typ = typ.Elem()
	fmt.Printf("*typ type: %s\n", typ.String())

	typ = typ.Elem()
	fmt.Printf("**typ type: %s\n", typ.String())

	fmt.Printf("Foo %d Bar %d Baz %d FooBar %d\n",
		foo, bar, baz, foobar)

	var big = make([]byte, 2)
	var small = big[0:2]
	copy(small, "12")
	fmt.Printf("%d %d %s %p\n", len(small), cap(small), small, small)
	small = append(small, '3')
	fmt.Printf("%d %d %s %p\n", len(small), cap(small), small, small)

	fmt.Printf("%d %d\n", uintptr(unsafe.Pointer(&small[0])), uintptr(unsafe.Pointer(&small[2])))
	var foo []int

	fmt.Printf("%s %p %d\n", foo, foo, len(foo))

	foo = append(foo, 1)
	fmt.Printf("%s %p\n", foo, foo)

	var bar map[int][]int

	fmt.Printf("%s %p %d\n", bar, bar, len(bar))

	fmt.Printf("%s %p %d\n", bar[0], bar[0], len(bar[0]))

	var baz = make(map[int][]int)
	baz[0] = []int{1}
	fmt.Printf("%s %p %d\n", baz[0], baz[0], len(baz[0]))

	addr := []byte{0, 1, 2, 3, 4, 5, 6}
	fmt.Printf("iso: %s\n", clns.ISOString(addr, false))
	fmt.Printf("iso: %s\n", clns.ISOString(addr, true))
	addr = addr[0:6]
	fmt.Printf("iso: %s\n", clns.ISOString(addr, false))

}
