// ===================================================
// Concrete implementation of TLV using bytes (octets)
// ===================================================

package tlv

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	// "golang.org/x/net/idna" for hostname
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
	TypeAreaAddrs   Type = 1 // ISO10590 (marshaled)
	TypeIsReach     Type = 2 // ISO10590
	TypeISNeighbors Type = 6 // ISO10590 (marshaled)

	//XXX Conflict!
	TypeIsVneighbors Type = 7 // ISO10590
	TypeInstanceID   Type = 7 // RFC6822

	TypePadding    Type = 8  // ISO10590 (marshaled)
	TypeSNPEntries Type = 9  // ISO10590 (marshaled)
	TypeAuth       Type = 10 // ISO10590
	TypePurge      Type = 13 // RFC6232 (marshaled)
	TypeLspBufSize Type = 14 // ISO10590 (marshaled)

	TypeFingerprint Type = 15 // RFC8196

	TypeExtIsReach Type = 22 // RFC5305

	TypeIPv4Iprefix   Type = 128 // RFC1195
	TypeNLPID         Type = 129 // RFC1195 (marshaled)
	TypeIPv4Eprefix   Type = 130 // RFC1195
	TypeIPv4IntfAddrs Type = 132 // RFC1195 (marshaled)
	TypeRouterID      Type = 134 // (marshaled)
	TypeExtIPv4Prefix Type = 135 // RFC5305
	TypeHostname      Type = 137 // RFC5301 (marshaled)
	TypeIPv6IntfAddrs Type = 232 // RFC5308 (marshaled)
	TypeIPv6Prefix    Type = 236 // RFC5308
	TypeRouterCap     Type = 242 // RFC7981
	TypeGenInfo       Type = 251 // RFC6823
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
	TypeGenInfo:       "TypeGenInfo",
}

// TypeNoPurge key presence in map indicates not allowed in Purge LSP (RFC6233)
// Allowed 7, 10, 13, 15, 137
var TypeNoPurge = map[int]struct{}{
	1: {}, 2: {}, 3: {}, 4: {}, 5: {}, 6: {},
	// 7: Instance ID
	8: {}, 9: {},
	// 10: Auth
	11: {}, 12: {},
	// 13: Optional Checksum
	14: {},
	// 15: Router-Fingerprint
	16: {},
	// 17-21: unassigned
	22: {}, 23: {}, 24: {}, 25: {},
	// 26-41: unassigned
	42: {},
	// 43-65: unassigned
	66: {},
	// 67-127: unassigned
	128: {}, 129: {}, 130: {}, 131: {}, 132: {}, 133: {}, 134: {}, 135: {}, 136: {},
	138: {}, 139: {}, 140: {}, 141: {}, 142: {}, 143: {}, 144: {}, 145: {}, 146: {}, 147: {}, 148: {}, 149: {}, 150: {},
	// 151-175: unassigned
	176: {}, 177: {},
	// 178-210: unassigned
	211: {},
	// 212-221: unassigned
	222: {}, 223: {},
	// 224-228: unassigned
	229: {},
	// 230-231: unassigned
	232: {}, 233: {}, 234: {}, 235: {}, 236: {}, 237: {}, 238: {}, 239: {}, 240: {}, 241: {}, 242: {}, 243: {},
	// 244-250: unassigned
	251: {},
	// 252-65535: unassigned

}

func (t Type) String() string {
	s, ok := TypeNameMap[t]
	if !ok {
		s = fmt.Sprintf("Unknown(%d)", t)
	}
	return s
}

// Type get type of byte based TLV
func (tlv Data) Type() (int, error) {
	if len(tlv) < 2 {
		return -1, fmt.Errorf("Can't get type of %d len TLV", len(tlv))
	}
	return int(tlv[0]), nil
}

// Length get length of byte based TLV
func (tlv Data) Length() (int, error) {
	if len(tlv) < 2 {
		return -1, fmt.Errorf("Can't get length of %d len TLV", len(tlv))
	}
	if len(tlv[2:]) < int(tlv[1]) {
		return -1, fmt.Errorf("Slice length %d < encoded TLV length %d",
			len(tlv[2:])-2,
			int(tlv[1]))
	}
	return int(tlv[1]), nil
}

// Value get value of byte based TLV
func (tlv Data) Value() ([]byte, error) {
	if _, err := tlv.Length(); err != nil {
		return nil, err
	}
	return tlv[2:], nil
}

// Authentication types
type AuthType uint8

const (
	AuthPlain   AuthType = 2
	AuthCrypto  AuthType = 3
	AuthMD5     AuthType = 54
	AuthPrivate AuthType = 255
)

func (tlv Data) newFixedValues(alen int, atyp interface{}) error {
	_, l, v, err := GetTLV(tlv)
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
	for aidx, i := 0, 0; i < count; i++ {
		addrs.Index(i).Set(reflect.ValueOf(v[aidx : aidx+alen]))
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
func (tlv Data) ParseTLV() (Map, error) {
	tlvmap := make(Map)

	tlvp := tlv
	for len(tlvp) > 1 {
		tlvtype := Type(tlvp[0])
		tlvlen := int(tlvp[1])
		// fmt.Printf("DEBUG: TLV Type %s Len %d\n", tlvtype, tlvlen)
		if tlvlen+2 > len(tlvp) {
			return nil, ErrTLVSpaceCorrupt(fmt.Sprintf("%d exceeds %d", tlvlen+2, len(tlvp)))
		}
		tlvmap[tlvtype] = append(tlvmap[tlvtype], tlvp[:tlvlen+2])
		tlvp = tlvp[tlvlen+2:]
	}
	return tlvmap, nil
}

// IntfIPv4AddrsValue returns slice of IPv4 interface addresses.
func (tlv Data) IntfIPv4AddrsDecode() ([]net.IP, error) {
	addrs := make([]net.IP, 0, 4)
	return addrs, tlv.newFixedValues(4, &addrs)
}

// IntfIPv6AddrsValue returns slice of IPv6 interface addresses.
func (tlv Data) IntfIPv6AddrsDecode() ([]net.IP, error) {
	addrs := make([]net.IP, 0, 4)
	return addrs, tlv.newFixedValues(16, &addrs)
}

// ISNeighborsValue return array of neighbor system IDs.
func (tlv Data) ISNeighborsDecode() ([]SystemID, error) {
	ids := make([]SystemID, 0, 2)
	return ids, tlv.newFixedValues(6, &ids)
}

type InstanceIDValue struct {
	Iid  uint16   `json:"iid"`
	Itid []uint16 `json:"itid"`
}

func (tlv Data) InstanceIDDecode() (InstanceIDValue, error) {
	rv := InstanceIDValue{}

	t, l, v, err := GetTLV(tlv)
	if err != nil {
		return rv, err
	}
	if l < 2 || l%2 == 1 {
		return rv, fmt.Errorf("incorrect len %d for type %s", l, Type(t))
	}
	rv.Iid = binary.BigEndian.Uint16(v)
	count := l/2 - 1
	if count > 0 {
		ids := make([]uint16, count)
		for i, j := 0, 0; i < count; i, j = i+1, j+2 {
			ids[i] = binary.BigEndian.Uint16(v[i:])
		}
		rv.Itid = ids
	}
	return rv, nil

}

// AreaAddrsValue returns an array of address found in the TLV.
func (tlv Data) AreaAddrsDecode() ([]clns.Area, error) {
	t, _, v, err := GetTLV(tlv)
	if err != nil {
		return nil, err
	}
	if t != int(TypeAreaAddrs) {
		return nil, fmt.Errorf("Incorrect TLV type %s expecting %s", Type(t), TypeAreaAddrs)
	}

	var addrs []clns.Area
	for len(v) > 0 {
		alen := int(v[0])
		if alen > len(v[1:]) {
			return nil, fmt.Errorf("Area address longer (%d) than available space (%d)", alen, len(v[1:]))
		}
		if alen == 0 {
			return nil, fmt.Errorf("Invalid zero-length area address")
		}
		addrs = append(addrs, v[1:1+alen])
		v = v[1+alen:]
	}
	return addrs, nil
}

func (tlv Data) Hostname() (string, error) {
	_, _, v, err := GetTLV(tlv)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(v)), nil

}

// RouterIDValue returns the Router ID found in the TLV.
func (tlv Data) RouterIDDecode() (net.IP, error) {
	_, l, v, err := GetTLV(tlv)
	if err != nil {
		return nil, err
	}
	if l != 4 {
		return nil, fmt.Errorf("Length of data %d is not 4", l)
	}
	return net.IP(v), nil
}

// NLPIDValues returns a slice of NLPID values.
func (tlv Data) NLPIDDecode() ([]clns.NLPID, error) {
	_, l, v, err := GetTLV(tlv)
	if err != nil {
		return nil, err
	}
	nlpids := make([]clns.NLPID, l)
	for i := 0; i < l; i++ {
		nlpids[i] = clns.NLPID(v[i])
	}
	return nlpids, nil
}

// LSPBufSizeValue returns the value found in the TLV.
func (tlv Data) LSPBufSizeDecode() (uint16, error) {
	_, l, v, err := GetTLV(tlv)
	if err != nil {
		return 0, err
	}
	if l != 2 {
		return 0, fmt.Errorf("Length of data %d is not 2", l)
	}
	return binary.BigEndian.Uint16(v), nil
}

// Return the systemid count returned in the input args.
func (tlv Data) PurgeDecode() ([]clns.SystemID, error) {
	_, l, v, err := GetTLV(tlv)
	if err != nil {
		return nil, err
	}
	if l != clns.SysIDLen+1 && l != 2*clns.SysIDLen+1 {
		return nil, fmt.Errorf("%s length %d not valid", TypePurge, l)
	}
	count := int(v[0])
	v = v[1:]
	if count < 1 || count > 2 {
		return nil, fmt.Errorf("%s invalid sysid count %d", TypePurge, count)
	}
	addrs := make([]clns.SystemID, 0, 2)
	for i := 0; i < 0; i++ {
		copy(addrs[i][:], v)
		v = v[clns.SysIDLen:]
	}
	return addrs, nil
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

type SNPEntry struct {
	Lifetime uint16
	Lspid    clns.LSPID
	SeqNo    uint32
	Cksum    uint16
}

func (tlv Data) SNPEntryDecode() ([]SNPEntry, error) {
	_, l, v, err := GetTLV(tlv)
	if err != nil {
		return nil, err
	}
	if l%SNPEntSize != 0 {
		return nil, ErrTLVSpaceCorrupt(
			fmt.Sprintf("SNP Entries TLV not multiple of %d", SNPEntSize))
	}
	count := l / SNPEntSize
	rv := make([]SNPEntry, count)
	for i := 0; i < count; i++ {
		rv[i].Lifetime = binary.BigEndian.Uint16(v[SNPEntLifetime:])
		copy(rv[i].Lspid[:], v[SNPEntLSPID:])
		rv[i].SeqNo = binary.BigEndian.Uint32(v[SNPEntSeqNo:])
		rv[i].Cksum = binary.BigEndian.Uint16(v[SNPEntCksum:])
		v = v[SNPEntSize:]
	}
	return rv, nil
}

type ISExtReach struct {
	Metric uint32      `json:"metric"`
	Nodeid clns.NodeID `json:"nodeid"`
	Subtlv Data        `json:"subtlv,omitempty"`
}

func (tlv Data) ISExtReachDecode() ([]ISExtReach, error) {
	t, l, v, err := GetTLV(tlv)
	if err != nil {
		return nil, err
	}
	count := 0
	for len(v) > 0 {
		if l < clns.NodeIDLen+3+1 {
			return nil, fmt.Errorf("short length %d for TLV %s", l, Type(t))
		}
		sublen := int(v[clns.NodeIDLen+3])
		if sublen != 0 {
			sub := v[clns.NodeIDLen+4:]
			if len(sub) != sublen {
				return nil, fmt.Errorf("subtlv length %d not equal to actual len %d", sublen, len(sub))
			}
		}
		nlen := 11 + sublen
		v = v[nlen:]
		l = l - nlen
		count++
	}
	// Extract the data
	_, _, v, _ = GetTLV(tlv)
	rv := make([]ISExtReach, count)
	for i := 0; i < count; i++ {
		rv[i].Metric = uint32(v[7])<<16 + uint32(v[8])<<8 + uint32(v[9])
		copy(rv[i].Nodeid[:], v)
		sublen := int(v[clns.NodeIDLen+3])
		if sublen != 0 {
			rv[i].Subtlv = make(Data, sublen)
			copy(rv[i].Subtlv, v[clns.NodeIDLen+4:])
		}
		nlen := 11 + sublen
		v = v[nlen:]
	}
	return rv, nil
}

// Constants for the Extended IPv4 and IPv6 Reachability encoding.
const (
	ExtIPFlagDown       = byte(1 << 7)
	ExtIPv4FlagSubTLV   = byte(1 << 6)
	ExtIPv4FlagLenMask  = byte(0x3f)
	ExtIPv6FlagExternal = byte(1 << 6)
	ExtIPv6FlagSubTLV   = byte(1 << 5)
	ExtIPMaxMetric      = uint32(0xFE000000)
)

// IPPrefix is the same as net.IPNet but we can then add methods like a JSON
// marshal function.
type IPPrefix net.IPNet

// MarshalText print an prefix in normal CIDR notation.
func (p IPPrefix) MarshalText() ([]byte, error) {
	return []byte((*net.IPNet)(&p).String()), nil
}

type IPPrefixCommon struct {
	Metric uint32   `json:"metric"`
	Prefix IPPrefix `json:"prefix"`
	Subtlv Data     `json:"subtlv,omitempty"`
	Updown bool     `json:"updown"`
}

type ExtIPv4Prefix struct {
	IPPrefixCommon
	ipbytes [4]byte
}

type IPv6Prefix struct {
	IPPrefixCommon
	External bool `json:"external"`
	ipbytes  [16]byte
}

func (tlv Data) IPPrefixCount() (int, error) {
	t, l, v, err := GetTLV(tlv)
	if err != nil {
		return 0, err
	}
	ipv4 := Type(t) == TypeExtIPv4Prefix
	count := 0
	for len(v) > 0 {
		if l < 5 {
			return 0, fmt.Errorf("short length %d for TLV %s", l, Type(t))
		}
		var gotsub bool
		var pfxlen int
		nlen := 5
		if ipv4 {
			gotsub = (ExtIPv4FlagSubTLV & v[4]) == 1
			pfxlen = int(ExtIPv4FlagLenMask & v[4])
		} else {
			gotsub = (ExtIPv6FlagSubTLV & v[4]) == 1
			pfxlen = int(v[5])
			nlen++
		}
		pfxblen := (pfxlen + 7) / 8
		nlen += pfxblen
		if gotsub {
			nlen += 1
		}
		if nlen > len(v) {
			return 0, fmt.Errorf("short length %d at least %d reqd for TLV %s", len(v), nlen, Type(t))
		}
		if gotsub {
			sublen := int(v[nlen-1])
			if sublen != 0 {
				sub := v[nlen:]
				if sublen > len(sub) {
					return 0, fmt.Errorf("subtlv length %d > remaining len %d", len(sub), sublen)
				}
			}
			nlen += sublen
		}
		v = v[nlen:]
		l = l - nlen
		count++
	}

	return count, nil
}

func (tlv Data) IPv4PrefixDecode() ([]ExtIPv4Prefix, error) {
	count, err := tlv.IPPrefixCount()
	if err != nil {
		return nil, err
	}

	_, _, v, _ := GetTLV(tlv)
	rv := make([]ExtIPv4Prefix, count)
	for i := 0; i < count; i++ {
		rv[i].Metric = binary.BigEndian.Uint32(v)
		gotsub := (ExtIPv4FlagSubTLV & v[4]) == 1
		pfxlen := int(ExtIPv4FlagLenMask & v[4])
		pfxblen := (pfxlen + 7) / 8
		nlen := 5 + pfxblen

		rv[i].Updown = (ExtIPFlagDown & v[4]) == 1
		rv[i].Prefix.IP = rv[i].ipbytes[:]
		rv[i].Prefix.Mask = net.CIDRMask(pfxlen, 32)
		copy(rv[i].Prefix.IP, v[5:])

		if gotsub {
			sublen := int(v[nlen])
			if sublen != 0 {
				rv[i].Subtlv = make(Data, sublen)
				copy(rv[i].Subtlv, v[nlen+1:])
			}
			nlen += 1 + sublen
		}
		v = v[nlen:]
	}
	return rv, nil
}

func (tlv Data) IPv6PrefixDecode() ([]IPv6Prefix, error) {
	count, err := tlv.IPPrefixCount()
	if err != nil {
		return nil, err
	}

	_, _, v, _ := GetTLV(tlv)
	rv := make([]IPv6Prefix, count)
	for i := 0; i < count; i++ {
		rv[i].Metric = binary.BigEndian.Uint32(v)
		gotsub := (ExtIPv6FlagSubTLV & v[4]) == 1
		pfxlen := int(v[5])
		pfxblen := (pfxlen + 7) / 8
		nlen := 6 + pfxblen

		rv[i].Updown = (ExtIPFlagDown & v[4]) == 1
		rv[i].External = (ExtIPv6FlagExternal & v[4]) == 1
		rv[i].Prefix.IP = rv[i].ipbytes[:]
		rv[i].Prefix.Mask = net.CIDRMask(pfxlen, 128)
		copy(rv[i].Prefix.IP, v[5:])

		if gotsub {
			sublen := int(v[nlen])
			if sublen != 0 {
				rv[i].Subtlv = make(Data, sublen)
				copy(rv[i].Subtlv, v[nlen+1:])
			}
			nlen += 1 + sublen
		}
		v = v[nlen:]
	}
	return rv, nil
}

func marshal(sb *strings.Builder, value interface{}, first *bool, err error) error {
	// Collect this common code here.
	if err != nil {
		return err
	}
	v, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if *first {
		*first = false
		fmt.Fprintf(sb, "%s", v)
	} else {
		fmt.Fprintf(sb, ", %s", v)
	}
	return nil
}

// MarshalJSON converts a tlv Map into JSON.
// nolint: gocyclo
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
		for _, tlv := range tlvs[k] {
			if firstent {
				firstent = false
				sb.WriteString("{ ")
			} else {
				sb.WriteString(", { ")
			}

			fmt.Fprintf(&sb, `"type": %d, "name": "%s", "value": `, k, k)

			var value interface{}
			var err error
			first := true

			switch k {
			case TypeAreaAddrs:
				value, err = tlv.AreaAddrsDecode()
			case TypeIPv4IntfAddrs:
				value, err = tlv.IntfIPv4AddrsDecode()
			case TypeIPv6IntfAddrs:
				value, err = tlv.IntfIPv6AddrsDecode()
			case TypeLspBufSize:
				value, err = tlv.LSPBufSizeDecode()
			case TypePurge:
				value, err = tlv.PurgeDecode()
			case TypeNLPID:
				value, err = tlv.NLPIDDecode()
			case TypeISNeighbors:
				value, err = tlv.ISNeighborsDecode()
			case TypeHostname:
				value, err = tlv.Hostname()
			case TypeRouterID:
				value, err = tlv.RouterIDDecode()
			case TypeExtIsReach:
				value, err = tlv.ISExtReachDecode()
			case TypeExtIPv4Prefix:
				value, err = tlv.IPv4PrefixDecode()
			case TypeIPv6Prefix:
				value, err = tlv.IPv6PrefixDecode()
			case TypeInstanceID:
				value, err = tlv.InstanceIDDecode()
			// Non-LSP
			case TypeSNPEntries:
				value, err = tlv.SNPEntryDecode()
			case TypePadding:
				value = "<padding>"
			// case TypeAuth:
			default:
				break
			}

			if value != nil {
				if err = marshal(&sb, value, &first, err); err != nil {
					return nil, err
				}
			} else {
				// Generic dump
				// Need to cast back to get normal behavior
				v := base64.StdEncoding.EncodeToString(tlv)
				if first {
					first = false
					fmt.Fprintf(&sb, "\"%s\"", v)
				} else {
					fmt.Fprintf(&sb, ", \"%s\"", v)
				}
			}
			sb.WriteString(" }")
			fmt.Println(sb.String())
		}
	}

	sb.WriteString("]")
	return []byte(sb.String()), nil
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
	if err := bt.newBuffer(); err != nil {
		panic("Unexpected newBuffer failure")
	}
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
