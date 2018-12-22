package tlv

import (
	"fmt"
	"net"
	"testing"
)

func TestTlvF(t *testing.T) {
	if false {
		t.Errorf("Fail the test")
	}
}

func TestNewIntfIPv4AddrsValue(t *testing.T) {
	b := Data{byte(TypeIPv4IntfAddrs),
		4,
		1, 2, 3, 4}
	addr := net.IPv4(1, 2, 3, 4)

	addrs, err := b.IntfIPv4AddrsValue()
	if err != nil {
		t.Errorf("%s", err)
	}
	if len(addrs) != 1 {
		t.Errorf("Returned address count not 1")
	}
	if !addr.Equal(addrs[0]) {
		t.Errorf("Returned address %s not %s", addrs[0], addr)
	}
	// if bytes.Compare(addrs[0], addr) != 0 {
	// 	t.Errorf("Returned address %s not %s", addrs[0], addr)
	// }
}

// NewIntfIPv6AddrsValue returns slice of IPv6 interface addresses
func TestNewIntfIPv6AddrsValue(t *testing.T) {
	b := Data{byte(TypeIPv6IntfAddrs),
		16,
		0xfc, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0xff,
	}
	addrs, err := b.IntfIPv6AddrsValue()
	if err != nil {
		t.Errorf("%s", err)
	}
	if len(addrs) != 1 {
		t.Errorf("Returned address count not 1")
	}

	addr := net.ParseIP("fc00::ff")
	if !addr.Equal(addrs[0]) {
		t.Errorf("Returned address %s not %s", addrs[0], addr)
	}
}

func TestISNeighborsValue(t *testing.T) {
	var nbrs []SystemID
	var err error
	b := Data{byte(TypeISNeighbors),
		6,
		1, 2, 3, 4, 5, 6}

	if nbrs, err = b.ISNeighborsValue(); err != nil {
		t.Errorf("Got Error: %s", err)
	}

	if len(nbrs) != 1 {
		t.Errorf("Wrong length of return value len %d cap %d",
			len(nbrs), cap(nbrs))
	}

	fmt.Printf("sysids: %s", nbrs)
	// Output: sysids: [0102.0304.0506]
}

// func BenchmarkTLV(b *testing.B) {
// 	for j := 0; j < 255; j++ {
// 		var buf []byte = make([]byte, 0, 255)
// 		elm := TLV{1, 2, buf}
// 		for i := 0; i < 255; i++ {
// 			elm.Length = byte(i + 1)
// 			elm.Value = elm.Value[:elm.Length]
// 			elm.Value[i] = byte(i)
// 		}
// 	}
// 	//fmt.Printf("len %d cap %d\n", len(elm.Value), cap(elm.Value))
// 	fmt.Printf("Done\n")
// }
