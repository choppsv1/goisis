// ===================================================
// Concrete implementation of TLV using bytes (octets)
// ===================================================

package tlv

import (
	"encoding/base64"
	"encoding/binary"
	// "encoding/json"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"net"
	"reflect"
	"sort"
	"strings"
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

func (s SystemID) String() string {
	rv := fmt.Sprintf("%02x%02x.%02x%02x.%02x%02x",
		s[0], s[1], s[2], s[3], s[4], s[5])
	return rv
}

// Type is a TLV type value
type Type uint8

// ISO 10589:2002
const (
	// ISO
	TypeAreaAddrs   Type = 1 // ISO10590
	TypeIsReach     Type = 2 // ISO10590
	TypeISNeighbors Type = 6 // ISO10590

	//XXX Conflict!
	TypeIsVneighbors Type = 7 // ISO10590
	TypeInstanceID   Type = 7

	TypePadding    Type = 8  // ISO10590
	TypeSNPEntries Type = 9  // ISO10590
	TypeAuth       Type = 10 // ISO10590
	TypePurge      Type = 13 // RFC6232
	TypeLspBufSize Type = 14 // ISO10590

	TypeExtIsReach Type = 22 //RFC5305

	TypeIPv4Iprefix   Type = 128 // RFC1195
	TypeNLPID         Type = 129 // RFC1195
	TypeIPv4Eprefix   Type = 130 // RFC1195
	TypeIPv4IntfAddrs Type = 132 // RFC1195
	TypeRouterID      Type = 134 // RFC1195
	TypeExtIPv4Prefix Type = 135 // RFC1195
	TypeHostname      Type = 137 // RFC1195
	TypeIPv6IntfAddrs Type = 232 // RFC1195
	TypeIPv6Prefix    Type = 236 // RFC1195
	TypeRouterCap     Type = 242 // RFC7981
)

// TypeNameMap returns string names for known TLV types
var TypeNameMap = map[Type]string{

	TypeAreaAddrs:     "TypeAreaAddrs",
	TypeIsReach:       "TypeIsReach",
	TypeISNeighbors:   "TypeISNeighbors",
	TypeInstanceID:    "TypeInstanceID",
	TypePadding:       "TypePadding",
	TypeSNPEntries:    "TypeSNPEntries",
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
	TypeRouterCap:     "TypeRouterCap",
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
	if len(b[2:]) < int(b[1]) {
		return -1, fmt.Errorf("Slice length %d < encoded TLV length %d",
			len(b[2:])-2,
			int(b[1]))
	}
	return int(b[1]), nil
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
	return string(e)
}

// Map is a map from TLV Type codes to an array of TLV data byte slices
type Map map[Type][]Data

// ParseTLV returns a map of slices of TLVs of by TLV Type. This validates the
// TLV lengths at the topmost level; however, it does not validate that the
// length is correct for the TLV type or that the data is correct.
func (b Data) ParseTLV() (Map, error) {
	tlv := make(Map)

	tlvp := b
	for len(tlvp) > 1 {
		tlvtype := Type(tlvp[0])
		tlvlen := int(tlvp[1])
		// fmt.Printf("DEBUG: TLV Type %s Len %d\n", tlvtype, tlvlen)
		if tlvlen+2 > len(tlvp) {
			return nil, ErrTLVSpaceCorrupt(fmt.Sprintf("%d exceeds %d", tlvlen+2, len(tlvp)))
		}
		tlv[tlvtype] = append(tlv[tlvtype], tlvp[:tlvlen+2])
		tlvp = tlvp[tlvlen+2:]
	}
	return tlv, nil
}

func (tlvs Map) MarshalJSON() ([]byte, error) {
	// Get sorted list of LSPIDs we have
	var sb strings.Builder
	if _, err := sb.WriteString("["); err != nil {
		return nil, err
	}

	keys := make([]Type, 0, len(tlvs))
	for k := range tlvs {
		keys = append(keys, k)
	}
	fmt.Println(keys)
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	fmt.Println(keys)

	firstent := true
	for _, k := range keys {
		if !firstent {
			sb.WriteString(", { ")
		} else {
			firstent = false
			sb.WriteString("{ ")
		}
		fmt.Fprintf(&sb, `"type": "%d", "name": "%s", "values": [ `, k, k)
		switch k {
		default:
			// Generic dump
			first := true
			var tlv []byte
			for _, tlv = range tlvs[k] {
				// Need to cast back to get normal behavior
				v := base64.StdEncoding.EncodeToString(tlv)
				if first {
					first = false
					fmt.Fprintf(&sb, "\"%s\"", v)
				} else {
					fmt.Fprintf(&sb, ", %s", v)
				}
			}
		}
		sb.WriteString(" ] }")
		fmt.Println(sb.String())
	}

	sb.WriteString("]")
	return []byte(sb.String()), nil
}

// IntfIPv4AddrsValue returns slice of IPv4 interface addresses.
func (b Data) IntfIPv4AddrsValue() ([]net.IP, error) {
	addrs := make([]net.IP, 0, 4)
	return addrs, b.newFixedValues(4, &addrs)
}

// IntfIPv6AddrsValue returns slice of IPv6 interface addresses.
func (b Data) IntfIPv6AddrsValue() ([]net.IP, error) {
	addrs := make([]net.IP, 0, 4)
	return addrs, b.newFixedValues(16, &addrs)
}

// ISNeighborsValue return array of neighbor system IDs.
func (b Data) ISNeighborsValue() ([]SystemID, error) {
	ids := make([]SystemID, 0, 2)
	return ids, b.newFixedValues(6, &ids)
}

// AreaAddrsValue returns an array of address found in the TLV.
func (b Data) AreaAddrsValue() ([][]byte, error) {
	var addrs [][]byte

	typ := Type(b[0])
	if typ != TypeAreaAddrs {
		return nil, fmt.Errorf("Incorrect TLV type %s expecting %s", Type(b[0]), TypeAreaAddrs)
	}

	alen := int(b[1])
	for valp := b[2 : alen+2]; len(valp) > 0; valp = valp[1+alen:] {
		alen = int(valp[0])
		if alen > len(valp[1:]) {
			return nil, fmt.Errorf("Area address longer (%d) than available space (%d)", alen, len(valp[1:]))
		}
		if alen == 0 {
			return nil, fmt.Errorf("Invalid zero-length area address")
		}
		addrs = append(addrs, valp[1:1+alen])
	}
	return addrs, nil
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

// LSPBufSizeValue returns the value found in the TLV.
func (b Data) LSPBufSizeValue() (uint16, error) {
	_, l, v, err := GetTLV(b)
	if err != nil {
		return 0, err
	}
	if l != 2 {
		return 0, fmt.Errorf("Length of data %d is not 2", l)
	}
	return binary.BigEndian.Uint16(v), nil
}

// TypeSNPEntries TLV value offsets
const (
	SNPEntLifetime = iota
	SNPEntLSPID    = SNPEntLifetime + 2
	SNPEntSeqNo    = SNPEntLSPID + clns.LSPIDLen
	SNPEntCksum    = SNPEntSeqNo + 4
	SNPEntSize     = SNPEntCksum + 2
)

// Slicer is a convenience function to return a slice given a start position and
// a length
func Slicer(b []byte, start int, length int) []byte {
	return b[start : start+length]
}

// SNPEntryValues returns slice of all SNPEntry values in the Map.
func (tlvs Map) SNPEntryValues() ([][]byte, error) {
	count := 0
	for _, b := range tlvs[TypeSNPEntries] {
		_, l, _, err := GetTLV(b)
		if err != nil {
			return nil, err
		}
		if l%SNPEntSize != 0 {
			return nil, ErrTLVSpaceCorrupt(
				fmt.Sprintf("SNP Entries TLV not multiple of %d", SNPEntSize))
		}
		count += l / SNPEntSize
	}
	entries := make([][]byte, count)
	ei := 0
	for _, b := range tlvs[TypeSNPEntries] {
		_, l, v, err := GetTLV(b)
		if err != nil {
			panic("err where none before")
		}
		// XXX this can be done faster using unsafe and just
		// constructing a new map with the backing array :)
		vi := 0
		count = l / SNPEntSize
		for i := 0; i < count; i++ {
			entries[ei] = Slicer(v, vi, SNPEntSize)
			vi += SNPEntSize
			ei++
		}
	}
	return entries, nil
}

// ===============================
// TLV Insertion Utliity Functions
// ===============================

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetOffset returns the length of bytes between cur and the packet start
// of p.
func GetOffset(start Data, cur Data) int {
	if cap(cur) == 0 {
		// This means we filled the buffer perfectly
		return len(start)
	}
	cp := uintptr(unsafe.Pointer(&cur[0]))
	startp := uintptr(unsafe.Pointer(&start[0]))
	return int(cp - startp)
}

// Track is used to track an open TLV.
type Track struct {
	Type   Type
	start  Data
	end    Data
	hdrend Data
	addhdr func(typ Type, b Data) (Data, error)
}

// Buffer is a buffer of TLV with an initialized header.
type Buffer struct {
	Hdr  Data // The TLV buffer.
	Tlvp Data // The TLV space.
	Endp Data // The end of the TLV data
}

// BufferTrack allows TLV insertion functions to allocate and track new TLV
// buffer space as the buffers fill up.
type BufferTrack struct {
	// Immutable
	Max  uint
	Size uint

	// Mutable
	Buffers []Buffer

	// Private
	offset uint
	finish func(Data, uint8) error
	t      Track
}

// NewBufferTrack returns a buffer tracker for inserting TLVs. 'size' is the
// size of the buffers, off is the offset to TLVs space in the buffer space, and
// 'max' is the maximum number of buffers. 'finish' is a function to initialize
// the header and further process the buffer (likely update the Update Process
// with new LSP segment data)
func NewBufferTrack(size, offset, max uint, finish func(Data, uint8) error) *BufferTrack {
	bt := &BufferTrack{
		Max:     max,
		Size:    size,
		Buffers: make([]Buffer, 0, 256),
		offset:  offset,
		finish:  finish,
	}
	bt.newBuffer()
	return bt
}

// NewSingleBufferTrack returns a simple Buffer track for use with an outside
// allocated and initialized buffer that will not be extended.
func NewSingleBufferTrack(tlvp Data) *BufferTrack {
	return &BufferTrack{
		Buffers: []Buffer{{
			Tlvp: tlvp,
			Endp: tlvp,
		}},
	}
}

func (bt *BufferTrack) closeBuffer() error {
	count := len(bt.Buffers)
	last := bt.Buffers[count-1]
	pstart := last.Hdr
	sz := GetOffset(pstart, last.Endp)
	return bt.finish(pstart[:sz], uint8(count)-1)
}

func (bt *BufferTrack) newBuffer() error {
	count := len(bt.Buffers)
	if count == int(bt.Max) {
		return fmt.Errorf("Exceeded maximum buffer space")
	}
	start := make([]byte, bt.Size)
	offset := bt.offset
	if count > 0 {
		// Assert there's space used here Tlvp, Endp
		if err := bt.closeBuffer(); err != nil {
			return err
		}
	}
	bt.Buffers = append(bt.Buffers, Buffer{start, start[offset:], start[offset:]})
	return nil
}

// Close the buffer tracker (will cause final finish to be called if non-empty)
func (bt *BufferTrack) Close() error {
	if bt.finish == nil {
		return nil
	}

	count := len(bt.Buffers)
	if count == 0 {
		return nil
	}

	last := bt.Buffers[count-1]
	if GetOffset(last.Tlvp, last.Endp) == 0 {
		return nil
	}

	return bt.closeBuffer()

}

// Check that the given TLV tracker has the required space.
func (t *Track) Check(reqd uint) error {
	l := uint(len(t.end))
	if l <= reqd {
		return ErrNoSpace{reqd, l}
	}
	return nil
}

func _open(t *Track) error {
	if len(t.start) < 2 {
		return ErrNoSpace{2, uint(len(t.start))}
	}
	t.start[0] = byte(t.Type)
	end := t.start[2:]
	if t.addhdr != nil {
		var err error
		if end, err = t.addhdr(t.Type, end); err != nil {
			return err
		}
	}
	t.hdrend = end
	t.end = end
	return nil
}

// Open a rolling TLV with optional function to add a header before the variable
// (Alloc) data, at the head of each new actual TLV is created.
func Open(p Data, typ Type, addheader func(Type, Data) (Data, error)) (Track, error) {
	t := Track{
		Type:   typ,
		start:  p,
		addhdr: addheader,
	}
	return t, _open(&t)
}

// Close an open TLV (sets the TLV length)
func (t *Track) Close() Data {
	// nil out the slices to help catch bugs
	t.start[1] = byte(GetOffset(t.start, t.end) - 2)
	t.start = nil
	end := t.end
	t.end = nil
	return end
}

// TopBuf returns the topmost (current) buffer in the buffer track.
func (bt *BufferTrack) TopBuf() *Buffer {
	return &bt.Buffers[len(bt.Buffers)-1]
}

// Alloc allocates space in an opened TLV, moves to next TLV if not enough space.
// Will return ErrNoSpace if the buffer cannot accommodate.
func (t *Track) Alloc(reqd uint) (Data, error) {
	if err := t.Check(reqd); err != nil {
		return nil, err
	}
	tlvlen := GetOffset(t.start, t.end) - 2
	if uint(tlvlen)+reqd > 255 {
		// No room left in TLV, close and re-open new TLV.
		t.start = t.Close()
		err := _open(t)
		if err != nil {
			return nil, err
		}
		// Check for room left in the buffer.
		if err := t.Check(reqd); err != nil {
			return nil, err
		}
	}
	p := t.end
	t.end = t.end[reqd:]
	return p, nil
}

// XXX use of separate Open() and Alloc() calls leaves open the possbility of
// "empty" TLVs (i.e., just a header of an entry based TLV) at the end of a buffer.
// Using OpenAllocTLV avoids this problem.

// OpenTLV opens a TLV in a BufferTrack with optional function to add a header
// before the variable data for each TLV that is created.
func (bt *BufferTrack) OpenTLV(typ Type, addheader func(Type, Data) (Data, error)) error {
	bt.t.Type = typ
	bt.t.start = bt.TopBuf().Endp
	bt.t.addhdr = addheader

	err := _open(&bt.t)
	if err == nil {
		return nil
	} else if _, nospace := err.(ErrNoSpace); !nospace {
		// Return error not from no space.
		return err
	}
	// Get more space.
	if err := bt.newBuffer(); err != nil {
		return err
	}
	bt.t.start = bt.Buffers[len(bt.Buffers)-1].Endp
	return _open(&bt.t)
}

// Alloc allocates space in an opened TLV inside a buffer tracker allowing for N
// TLVs to occur over M (max) buffers.
func (bt *BufferTrack) Alloc(reqd uint) (Data, error) {
	p, err := bt.t.Alloc(reqd)
	if err == nil {
		// Good!
		return p, nil
	}

	// Return error not from no space.
	_, nospace := err.(ErrNoSpace)
	if !nospace {
		// Unexpected error.
		return nil, err
	}

	// Close the TLV but only keep it if it's non-empty, we know it was
	// supposed to have data as the user is trying to Alloc it here.
	bt.CloseTLV(true)

	// Get more space.
	if err := bt.newBuffer(); err != nil {
		return nil, err
	}

	// Open another TLV of same type with required allocation.
	// Possible recursion, but as we have just made the space available
	// with a new buffer it won't happen again.
	return bt.OpenWithAlloc(reqd, bt.t.Type, bt.t.addhdr)
}

// Add allocates space for and adds the value in the slice 'b'
func (bt *BufferTrack) Add(b []byte) error {
	p, err := bt.Alloc(uint(len(b)))
	if err != nil {
		return err
	}
	copy(p, b)
	return nil
}

// OpenWithAlloc opens a TLV and allocates the first entry from a BufferTrack getting new buffer if needed.
func (bt *BufferTrack) OpenWithAlloc(reqd uint, typ Type, addheader func(Type, Data) (Data, error)) (Data, error) {
	if err := bt.OpenTLV(typ, addheader); err != nil {
		return nil, err
	}
	return bt.Alloc(reqd)
}

// OpenWithAdd opens a TLV and allocates the first entry from a BufferTrack getting new buffer if needed.
func (bt *BufferTrack) OpenWithAdd(b []byte, typ Type, addheader func(Type, Data) (Data, error)) error {
	if err := bt.OpenTLV(typ, addheader); err != nil {
		return err
	}
	return bt.Add(b)
}

// CloseTLV closes the open TLV and updates the buffer if:
//   1) dumpEmpty is false; or
//   2) there non-header data present
func (bt *BufferTrack) CloseTLV(dumpEmpty bool) {
	if dumpEmpty && GetOffset(bt.t.hdrend, bt.t.end) == 0 {
		// Here we are closing a TLV that we wanted to add some entry
		// data to. dumpEmpty means the semantics are that data is
		// expected, and if there's none in the existing Open TLV we
		// should just forget it rather than close it and have an empty
		// useless entry TLV in the buffer.
		bt.t.start, bt.t.end = nil, nil
	} else {
		bt.Buffers[len(bt.Buffers)-1].Endp = bt.t.Close()
	}
}

// EndSpace returns the current end of the packet buffer space.
func (bt *BufferTrack) EndSpace() Data {
	return bt.Buffers[len(bt.Buffers)-1].Endp
}

// ===============================
// TLV Concrete Insertion Functions
// ===============================

// Done is marker returned on a channels when the information is done being
// sent, by whomever was sending it.
type Done struct{}

func drainChannel(C <-chan interface{}, count *int) {
	for *count > 0 {
		result, ok := <-C
		if !ok {
			return
		}
		if _, ok := result.(Done); ok {
			*count--
		}
	}
}

// AddAreas adds the given areas in a TLV[s]. We expect and required everything
// to be in one TLV here.
func (bt *BufferTrack) AddAreas(areaIDs [][]byte) error {
	if len(areaIDs) == 0 {
		return nil
	}

	reqd := 0
	for i := 0; i < len(areaIDs); i++ {
		reqd += 1 + len(areaIDs[i])
	}

	p, err := bt.OpenWithAlloc(uint(reqd), TypeAreaAddrs, nil)
	if err != nil {
		return err
	}

	for _, a := range areaIDs {
		p[0] = uint8(len(a))
		copy(p[1:], a)
		p = p[p[0]+1:]
	}

	bt.CloseTLV(true)
	return nil
}

// AddAdjSNPA adds SNPA of all up adjacencies.
func (bt *BufferTrack) AddAdjSNPA(addrs []net.HardwareAddr) error {
	if err := bt.OpenTLV(TypeISNeighbors, nil); err != nil {
		return err
	}
	for _, addr := range addrs {
		if err := bt.Add(addr); err != nil {
			return err
		}
	}
	bt.CloseTLV(true)
	return nil
}

// AdjInfo is received on a channel to describe adjacencies.
type AdjInfo struct {
	Metric uint32
	Nodeid clns.NodeID
	Subtlv []byte
}

// AddExtISReach reads AdjInfo from the channel C adding the information to
// Extended IS Reachability TLV[s] (RFC5305). It stops reading from the channel
// after it has read count AdjDone values.
func (bt *BufferTrack) AddExtISReach(c <-chan interface{}, count int) error {
	defer drainChannel(c, &count)

	if err := bt.OpenTLV(TypeExtIsReach, nil); err != nil {
		return err
	}
	for count > 0 {
		result, ok := <-c
		if !ok {
			return fmt.Errorf("Early close on adjinfo channel remaining: %d", count)
		}
		if _, ok := result.(Done); ok {
			count--
			continue
		}

		adj := result.(AdjInfo)
		tlvp, err := bt.Alloc(clns.NodeIDLen + uint(4) + uint(len(adj.Subtlv)))
		if err != nil {
			return err
		}

		// Write big endian starting in last nodeid byte since
		// metric is 3 bytes long.
		binary.BigEndian.PutUint32(tlvp[clns.SysIDLen:], adj.Metric)

		// Now copy the node ID which will overwrite the MSB of the metric
		copy(tlvp, adj.Nodeid[:])

		// Now copy the node ID which will overwrite the MSB of the metric
		sublen := len(adj.Subtlv)
		if sublen > 0 {
			tlvp[clns.NodeIDLen+3] = byte(sublen)
			copy(tlvp[clns.NodeIDLen+4:], adj.Subtlv)
		}
	}

	bt.CloseTLV(true)
	return nil
}

// --------------------------
// Extended IPv4 Reachability
// --------------------------

// Constants for the Extended IPv4 Reachability encoding.
const (
	ExtIPFlagDown       = byte(1 << 7)
	ExtIPv4FlagSubTLV   = byte(1 << 6)
	ExtIPv6FlagExternal = byte(1 << 6)
	ExtIPv6FlagSubTLV   = byte(1 << 5)
	ExtIPMaxMetric      = uint32(0xFE000000)
)

// IPInfo is received on a channel to describe adjacencies.
type IPInfo struct {
	Metric uint32
	Ipnet  net.IPNet
	Subtlv []byte
}

func lenExtIP(ipi *IPInfo) uint {
	isv4 := ipi.Ipnet.IP.To4() != nil
	clen := 5
	if !isv4 {
		// Add extra prefix len byte
		clen++
	}

	mlen, _ := ipi.Ipnet.Mask.Size()
	blen := (mlen + 7) / 8
	sublen := len(ipi.Subtlv)

	tlen := uint(clen + blen + sublen)
	if sublen > 0 {
		tlen++
	}
	return tlen
}

// extIPEncoding encodes the IP into the TLV in Ext IP Reach format
func encodeExtIP(tlvp []byte, ipi *IPInfo) {
	binary.BigEndian.PutUint32(tlvp, ipi.Metric)
	tlvp = tlvp[4:]

	isv4 := ipi.Ipnet.IP.To4() != nil
	mlen, _ := ipi.Ipnet.Mask.Size()
	blen := uint(mlen+7) / 8
	sublen := uint(len(ipi.Subtlv))

	// if !up {
	//      tlvp[0] |= ExtIPFlagDown
	// }
	if sublen > 0 {
		if isv4 {
			tlvp[0] |= ExtIPv4FlagSubTLV
		} else {
			tlvp[0] |= ExtIPv6FlagSubTLV
		}
	}
	if isv4 {
		tlvp[0] |= byte(mlen)
		tlvp = tlvp[1:]
	} else {
		tlvp[1] = byte(mlen)
		tlvp = tlvp[2:]
	}
	copy(tlvp, ipi.Ipnet.IP[:blen])
	if sublen > 0 {
		tlvp[blen] = byte(sublen)
		copy(tlvp[1+blen:], ipi.Subtlv)
	}
}

// AddExtIPReach reads IPInfo from the channel C adding the information to
// Extended Reachability TLV[s]. It stops reading from the channel after it has
// read count AdjDone values.
func (bt *BufferTrack) AddExtIPReach(ipv4 bool, c <-chan interface{}, count int) error {
	defer drainChannel(c, &count)

	typ := TypeExtIPv4Prefix
	if !ipv4 {
		typ = TypeIPv6Prefix
	}
	if err := bt.OpenTLV(typ, nil); err != nil {
		return err
	}
	for count > 0 {
		result, ok := <-c
		if !ok {
			return fmt.Errorf("Early close on adjinfo channel remaining: %d", count)
		}
		if _, ok := result.(Done); ok {
			count--
			continue
		}

		ipi := result.(IPInfo)
		tlvp, err := bt.Alloc(lenExtIP(&ipi))
		if err != nil {
			return err
		}
		encodeExtIP(tlvp, &ipi)
	}

	bt.CloseTLV(true)
	return nil
}

// AddHostname adds hostname TLV if hostname is not nil.
func (bt *BufferTrack) AddHostname(hostname string) error {
	if len(hostname) == 0 {
		return nil
	}
	err := bt.OpenWithAdd([]byte(hostname), TypeHostname, nil)
	if err == nil {
		bt.CloseTLV(true)
	}
	return err
}

// AddIntfAddrs adds all ip addresses as interface addresses
func (bt *BufferTrack) AddIntfAddrs(addrs []net.IPNet) error {
	if len(addrs) == 0 {
		return nil
	}
	if ok := addrs[0].IP.To4(); ok != nil {
		if err := bt.OpenTLV(TypeIPv4IntfAddrs, nil); err != nil {
			return err
		}
		for _, addr := range addrs {
			if err := bt.Add(addr.IP.To4()); err != nil {
				return err
			}
		}
	} else {
		if err := bt.OpenTLV(TypeIPv6IntfAddrs, nil); err != nil {
			return err
		}
		for _, addr := range addrs {
			if err := bt.Add(addr.IP.To16()); err != nil {
				return err
			}
		}
	}
	bt.CloseTLV(true)
	return nil
}

// AddNLPID adds the array of NLPID to the packet in a TLV
func (bt *BufferTrack) AddNLPID(nlpid []byte) error {
	if len(nlpid) == 0 {
		return nil
	}
	err := bt.OpenWithAdd(nlpid, TypeNLPID, nil)
	bt.CloseTLV(true)
	return err
}

// AddPadding adds the largest padding TLV that will fit in the packet buffer.
// Only used in IIH so don't bother with handling BufferTrack
func AddPadding(p Data) (Data, error) {
	tlvlen := min(255, len(p)-2)
	if tlvlen < 0 {
		return nil, ErrNoSpace{2, uint(len(p))}
	}
	p[0] = byte(TypePadding)
	p[1] = byte(tlvlen)
	return p[2+tlvlen:], nil
}
