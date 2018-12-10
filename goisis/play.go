package main

//
// play.go is a playground area for validating/understanding things
//

import (
	"fmt"
	// "github.com/choppsv1/goisis/raw"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/tlv"
	"reflect"
	"sync"
	"time"
	"unsafe"
)

type addr []byte

const (
	foo = iota + 3
	bar
	baz = iota + 8
	foobar
)

type myint int

func (mi myint) gofunc(wg *sync.WaitGroup) {
	fmt.Println(mi)
	wg.Done()
}

type Bar struct {
	i int
}

type Foo struct {
	myMap map[[2]byte]*Bar
}

func NewFoo() *Foo {
	foo := &Foo{
		myMap: make(map[[2]byte]*Bar),
	}
	return foo
}

func playground() {

	mac1 := clns.HWToSNPA(clns.AllL1IS)
	fmt.Printf("MAC %v\n", mac1)

	// mac2 := clns.HWAddr(clns.AllL1IS).ToSNPA()
	// fmt.Printf("MAC %v\n", mac2)

	foo1 := NewFoo()
	foo2 := NewFoo()

	fmt.Printf("Foo1 %p Foo2 %p\n", foo1.myMap, foo2.myMap)

	// var snpe tlv.SNPEntry
	// fmt.Printf("OffsetOf Lifetime: %u\n", unsafe.Offsetof(snpe.Lifetime))
	// fmt.Printf("OffsetOf LSPID: %u\n", unsafe.Offsetof(snpe.LSPID))
	// fmt.Printf("OffsetOf SeqNo: %u\n", unsafe.Offsetof(snpe.SeqNo))
	// fmt.Printf("OffsetOf Chksum: %u\n", unsafe.Offsetof(snpe.Chksum))

	fmt.Println(dlogger.Prefix())
	fmt.Println(logger.Prefix())

	t := time.AfterFunc(10*time.Second, func() {})
	fmt.Printf("Timer %p.Stop() == %v\n", t, t.Stop())
	fmt.Printf("Timer %p.Stop() == %v\n", t, t.Reset(10*time.Second))
	fmt.Printf("Timer %p.Stop() == %v\n", t, t.Stop())
	fmt.Printf("Timer %p.Stop() == %v\n", t, t.Stop())

	m := make(map[int]int)
	v := m[0]
	fmt.Printf("val: %d\n", v)

	arr := [3]int{0, 1, 2}
	aslice := arr[:]
	fmt.Printf("typeof aslice %v\n", reflect.TypeOf(aslice))
	var arrp *[3]int
	arrp = &arr
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&aslice))
	arrp = (*[3]int)(unsafe.Pointer(hdr.Data))
	fmt.Printf("arrp %v\n", arrp)

	// ip, net := raw.GetInterfacePrefix("vboxnet3")
	// fmt.Printf("interface addr: %s net: %s\n", ip, net)

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

	// Read that this wouldn't work, but didn't agree with the reasoning.
	// the author claimed that 'mi' would only be evaluated when the go
	// routine ran and so could all be the same final value, but the
	// variable has to actually bind at time of eval b/c I think it
	// represents just another argument to the function.
	//
	wg := sync.WaitGroup{}
	li := []myint{1, 2, 3, 4}
	for _, mi := range li {
		wg.Add(1)
		go mi.gofunc(&wg)
	}
	wg.Wait()
}
