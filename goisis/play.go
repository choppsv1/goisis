package main

//
// play.go is a playground area for validating/understanding things
//

import (
	"fmt"
	// "github.com/choppsv1/goisis/raw"
	"github.com/choppsv1/goisis/tlv"
	"reflect"
)

type addr []byte

const (
	foo = iota + 3
	bar
	baz = iota + 8
	foobar
)

func playground() {
	var tlvArray = []byte{1, 1, 0xff}
	var tlvData = tlv.Data(tlvArray[:])
	var tlvBData = []byte(tlvData)
	var ab = make([]byte, 6)
	var a addr = ab

	// ip, net := raw.GetInterfacePrefix("vboxnet3")
	// fmt.Printf("interface addr: %s net: %s\n", ip, net)

	tlv.TLV.Type(tlvData)
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
}
