package main

//
// play.go is a playground area for validating/understanding things
//

import (
	"fmt"
	"github.com/choppsv1/goisis/tlv"
	"reflect"
	//"sync"
	"time"
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

	val := 0x132
	fmt.Printf("%#08x %#04x\n", val, val)

	dur := time.Duration(3200001) * time.Nanosecond
	fmt.Printf("%v\n", dur)

	// // Signals are tossed if no-one is waiting.
	// // can be seen by removing or adding the sleep
	// lock := sync.Mutex{}
	// cond := sync.NewCond(&lock)
	// wg := sync.WaitGroup{}
	// wg.Add(2)

	// condfunc := func() {
	// 	for i := 0; i < 10; i++ {
	// 		cond.L.Lock()
	// 		cond.Wait()
	// 		fmt.Printf("Cond Awoke: %d\n", i)
	// 		cond.L.Unlock()
	// 	}
	// 	fmt.Printf("Cond Done\n")
	// 	wg.Done()
	// }
	// go condfunc()
	// go condfunc()
	// for i := 0; i < 20; i++ {
	// 	time.Sleep(time.Millisecond * 100)
	// 	fmt.Printf("Sending Signal %d\n", i)
	// 	cond.Signal()
	// }
	// wg.Wait()
}
