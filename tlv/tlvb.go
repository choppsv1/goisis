// ===================================================
// Concrete implementation of TLV using bytes (octets)
// ===================================================

package tlv

import (
	"fmt"
	"net"
	"reflect"
	"unsafe"
)

// TLV of byte data
//        octet  octet   ...
//      [ type ][ len ][ len bytes of data ]
//

// Data is a byte slice that should start with type and len values
type Data []byte

// NLPID is a ISO network layer process identifier
type NLPID uint8

// SystemID is a byte address of fixed (6) length
type SystemID []byte

// ErrNoSpace is returns from TLV adding routines when there is not enough space
// to continue.
type ErrNoSpace struct {
	required, capacity int
}

func (e ErrNoSpace) Error() string {
	return "Not enough space in PDU for TLV"
}

func (s SystemID) String() string {
	rv := fmt.Sprintf("%02x%02x.%02x%02x.%02x%02x",
		s[0], s[1], s[2], s[3], s[4], s[5])
	return rv
}

// Type is a TLV type value
type Type uint8

// ISO 10589:2002
const (
	TypeAreaAddrs   Type = 1
	TypeIsReach          = 2
	TypeISNeighbors      = 6

	//XXX Conflict!
	TypeIsVneighbors = 7
	TypeInstanceID   = 7

	TypePadding    = 8
	TypeSnpEntries = 9
	TypeAuth       = 10
	TypeLspBufSize = 14

	//RFC5305
	TypeExtIsReach = 22

	//RFC1195
	TypeIPv4Iprefix   = 128
	TypeNLPID         = 129
	TypeIPv4Eprefix   = 130
	TypeIPv4IntfAddrs = 132
	TypeRouterID      = 134
	TypeExtIPv4Prefix = 135
	TypeHostname      = 137
	TypeIPv6IntfAddrs = 232
	TypeIPv6Prefix    = 236
)

// TypeNameMap returns string names for known TLV types
var TypeNameMap = map[Type]string{

	TypeAreaAddrs:     "TypeAreaAddrs",
	TypeIsReach:       "TypeIsReach",
	TypeISNeighbors:   "TypeISNeighbors",
	TypeInstanceID:    "TypeInstanceID",
	TypePadding:       "TypePadding",
	TypeSnpEntries:    "TypeSnpEntries",
	TypeAuth:          "TypeAuth",
	TypeLspBufSize:    "TypeLspBufSize",
	TypeExtIsReach:    "TypeExtIsReach",
	TypeIPv4Iprefix:   "TypeIPv4Iprefix",
	TypeNLPID:         "TypeNLPID",
	TypeIPv4Eprefix:   "TypeIPv4Eprefix",
	TypeIPv4IntfAddrs: "TypeIPv4IntfAddrs",
	TypeRouterID:      "TypeRouterID",
	TypeExtIPv4Prefix: "TypeExtIPv4Prefix",
	TypeHostname:      "TypeHostname",
	TypeIPv6IntfAddrs: "TypeIPv6IntfAddrs",
	TypeIPv6Prefix:    "TypeIPv6Prefix",
}

func (t Type) String() string {
	s, ok := TypeNameMap[t]
	if !ok {
		s = fmt.Sprintf("Unknown(%d)", t)
	}
	return s
}

// newTLVFunc := map[int]func (Data) () (inteface{}, error)
//TLV_TYPES = {
//     TLV_AREA_ADDRS: AreaAddrTLV,
//     TLV_IS_REACH: ISReachTLV,
//     TLV_IS_NEIGHBORS: ISNeighborsTLV,
//     TLV_IS_VNEIGHBORS: ISVNeighborsTLV,
//     TLV_PADDING: PaddingTLV,
//     TLV_IPV4_INTF_ADDRS: IPV4IntfAddrsTLV,
//     TLV_ROUTER_ID: RouterIDTLV,
//     TLV_NLPID: NLPIDTLV,
//     TLV_SNP_ENTRIES: SNPEntriesTLV,
//     TLV_EXT_IS_REACH: ExtISReachTLV,
//     TLV_IPV4_IPREFIX: IPV4PrefixesTLV,
//     TLV_IPV4_EPREFIX: IPV4PrefixesTLV,
//     TLV_EXT_IPV4_PREFIX: ExtIPV4PrefixesTLV,
//     TLV_HOSTNAME: HostnameTLV,
//     TLV_IPV6_INTF_ADDRS: IPV6IntfAddrsTLV,
//     TLV_IPV6_PREFIX: IPV6PrefixesTLV,
// }

// Type get type of byte based TLV
func (b Data) Type() (int, error) {
	if len(b) < 2 {
		return -1, fmt.Errorf("Can't get type of %d len TLV", len(b))
	}
	return int(b[0]), nil
}

// Length get length of byte based TLV
func (b Data) Length() (int, error) {
	if len(b) < 2 {
		return -1, fmt.Errorf("Can't get length of %d len TLV", len(b))
	}
	if len(b[2:]) != int(b[1]) {
		return -1, fmt.Errorf("Slice length %d != encoded TLV length %d",
			len(b[2:]),
			int(b[1]))
	}
	return len(b[2:]), nil
}

// Value get value of byte based TLV
func (b Data) Value() ([]byte, error) {
	if _, err := b.Length(); err != nil {
		return nil, err
	}
	return b[2:], nil
}

func (b Data) newFixedValues(alen int, atyp interface{}) error {
	_, l, v, err := GetTLV(b)
	if err != nil {
		return err
	}
	if (l % alen) != 0 {
		return fmt.Errorf("Length of data %d is not multiple of value length %d", l, alen)
	}

	count := l / alen

	// Get a new slice of the same type passed in.
	aval := reflect.ValueOf(atyp) // Interface Pointer Value
	ptyp := aval.Elem().Type()    // Type Pointed To
	addrs := reflect.MakeSlice(ptyp, count, count)

	// Set the input slice up
	aval.Elem().Set(addrs)

	// Fill the input slice up.
	for aidx := 0; aidx < count; aidx++ {
		addrs.Index(aidx).Set(reflect.ValueOf(v[aidx : aidx+alen]))
		aidx += alen

	}
	return nil
}

// ========================
// TLV Extraction Functions
// ========================

// ErrTLVSpaceCorrupt is returned if while parsing TLVs we run past the
// allocated space.
type ErrTLVSpaceCorrupt string

func (e ErrTLVSpaceCorrupt) Error() string {
	return fmt.Sprintf("%s", string(e))
}

// ParseTLV returns a map of slices of TLVs of by TLV Type. This validates the
// TLV lengths at the topmost level; however, it does not validate that the
// length is correct for the TLV type or that the data is correct.
func (b Data) ParseTLV() (map[Type][]Data, error) {
	tlv := make(map[Type][]Data)

	tlvp := b
	for len(tlvp) > 1 {
		tlvtype := Type(tlvp[0])
		tlvlen := int(tlvp[1])
		fmt.Printf("DEBUG: TLV Type %s Len %d\n", tlvtype, tlvlen)
		if tlvlen+2 > len(tlvp) {
			return nil, ErrTLVSpaceCorrupt(fmt.Sprintf("%d exceeds %d", tlvlen+2, len(tlvp)))
		}
		tlv[tlvtype] = append(tlv[tlvtype], tlvp)
		tlvp = tlvp[tlvlen+2:]
	}
	return tlv, nil
}

// NewIntfIPv4AddrsValue returns slice of IPv4 interface addresses.
func (b Data) NewIntfIPv4AddrsValue(addrs *[]net.IP) error {
	if err := b.newFixedValues(4, addrs); err != nil {
		return err
	}
	return nil
}

// NewIntfIPv6AddrsValue returns slice of IPv6 interface addresses.
func (b Data) NewIntfIPv6AddrsValue(addrs *[]net.IP) error {
	return b.newFixedValues(16, addrs)
}

// NewISNeighborsValue return array of neighbor system IDs.
func (b Data) NewISNeighborsValue(ids *[]SystemID) error {
	return b.newFixedValues(6, ids)
}

// RouterIDValue returns the Router ID found in the TLV.
func (b Data) RouterIDValue() (net.IP, error) {
	_, l, v, err := GetTLV(b)
	if err != nil {
		return nil, err
	}
	if l != 4 {
		return nil, fmt.Errorf("Length of data %d is not 4", l)
	}
	return net.IP(v), nil
}

// NLPIDValues returns a slice of NLPID values.
func (b Data) NLPIDValues(nlpids *[]NLPID) error {
	return b.newFixedValues(1, nlpids)
}

// =======================
// TLV Insertion Functions
// =======================

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetPacketOffset returns the length of bytes between cur and the packet start
// of p.
func GetPacketOffset(p Data, cur Data) int {
	if cap(cur) == 0 {
		// This just means we fill the buffer perfectly
		return len(p)
	}

	cp := uintptr(unsafe.Pointer(&cur[0]))
	pp := uintptr(unsafe.Pointer(&p[0]))
	return int(cp - pp)
}

// AddPadding adds the largest padding TLV that will fit in the packet buffer.
func AddPadding(p Data) (Data, error) {
	tlvlen := min(255, cap(p)-2)
	if tlvlen < 0 {
		return nil, ErrNoSpace{2, cap(p)}
	}
	p[0] = TypePadding
	p[1] = byte(tlvlen)
	return p[2+tlvlen:], nil
}

// AddArea adds the given area in a TLV.
func AddArea(p Data, areaID []byte) (Data, error) {
	tlvlen := len(areaID) + 1
	if 2+tlvlen > cap(p) {
		return nil, ErrNoSpace{2 + tlvlen, cap(p)}
	}
	p[0] = uint8(TypeAreaAddrs)
	p[1] = byte(tlvlen)
	p[2] = byte(tlvlen - 1)
	copy(p[3:], areaID)

	return p[2+tlvlen:], nil
}

// AddNLPID adds the array of NLPID to the packet in a TLV
func AddNLPID(p Data, nlpid []byte) (Data, error) {
	tlvlen := len(nlpid)
	if 2+tlvlen > cap(p) {
		return nil, ErrNoSpace{2 + tlvlen, cap(p)}
	}
	p[0] = TypeNLPID
	p[1] = byte(tlvlen)
	copy(p[2:], nlpid)

	return p[2+tlvlen:], nil
}

// Track is used to track an open TLV.
type Track struct {
	start   Data
	end     Data
	typ     Type
	addhead func(*Track) error
}

func _open(t *Track) error {
	if len(t.start) < 2 {
		return ErrNoSpace{2, len(t.start)}
	}
	t.start[0] = byte(t.typ)
	t.end = t.start[2:]
	if t.addhead != nil {
		return t.addhead(t)
	}
	return nil
}

// Open a TLV with optional function to add a header before the variable data.
func Open(p Data, typ Type, addhead func(*Track) error) (*Track, error) {
	t := &Track{p, nil, typ, addhead}
	err := _open(t)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// Alloc allocates space in an opened TLV.
func Alloc(t *Track, reqd int) (Data, error) {
	if len(t.end) < reqd {
		return nil, ErrNoSpace{reqd, len(t.end)}
	}
	tlvlen := GetPacketOffset(t.start, t.end)
	if tlvlen+reqd > 255 {
		t.start[1] = byte(tlvlen)
		t.start = t.end
		err := _open(t)
		if err != nil {
			return nil, err
		}
		// Header may have been added.
		tlvlen = GetPacketOffset(t.start, t.end)
		if tlvlen+reqd > 255 {
			return nil, ErrNoSpace{reqd, 255}
		}
	}
	if tlvlen+reqd > len(t.end) {
		return nil, ErrNoSpace{tlvlen + reqd, len(t.end)}
	}
	p := t.end
	t.end = t.end[reqd:]
	return p, nil
}

// Close an open TLV.
func Close(t *Track) Data {
	t.start[1] = byte(GetPacketOffset(t.start, t.end))
	return t.end
}

// AddAdjSNPA adds SNPA of all up adjacencies.
func AddAdjSNPA(p Data, addrs []net.HardwareAddr) (Data, error) {
	if len(addrs) == 0 {
		return p, nil
	}

	tlv, err := Open(p, TypeISNeighbors, nil)
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		var p Data

		alen := len(addr)
		if p, err = Alloc(tlv, alen); err != nil {
			return nil, err
		}
		copy(p, addr)
	}
	return Close(tlv), nil
}
