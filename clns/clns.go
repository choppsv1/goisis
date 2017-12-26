package clns

import (
	"encoding/hex"
	"fmt"
	"github.com/choppsv1/goisis/pkt"
	"net"
	"strings"
)

// ===============================
// Packet Headers (offset values).
// ===============================

// ------------------------------------
// ISO 10589 CLNS header offset values.
// ------------------------------------
const (
	HdrLLCSSAP = iota // 802.2 LLC header offset values
	HdrLLCDSAP        // 802.2 LLC header offset values
	HdrLLCCTRL        // 802.2 LLC header offset values

	HdrCLNSIDRP
	HdrCLNSLen
	HdrCLNSVer
	HdrCLNSSysIDLen
	HdrCLNSPDUType
	HdrCLNSVer2
	HdrCLNSResv
	HdrCLNSMaxArea
	HdrCLNSSize
)

// HdrLLCSize is the size of the LLC header we use.
const HdrLLCSize = 3

// ---------------------------
// IIH - Common header offsets
// ---------------------------
const (
	HdrIIHCircType = iota
	HdrIIHSrcID
	HdrIIHHoldTime = HdrIIHSrcID + SysIDLen
	HdrIIHPDULen   = HdrIIHHoldTime + 2
)

// -------------------------------------
// IIH - LAN Hello header offset values.
// -------------------------------------
const (
	HdrIIHLANCircType = HdrIIHCircType
	HdrIIHLANSrcID    = HdrIIHSrcID
	HdrIIHLANHoldTime = HdrIIHHoldTime
	HdrIIHLANPDULen   = HdrIIHPDULen
	HdrIIHLANPriority = HdrIIHLANPDULen + 2
	HdrIIHLANLANID    = HdrIIHLANPriority + 1
	HdrIIHLANSize     = HdrIIHLANLANID + LANIDLen
)

// -------------------------------------
// IIH - P2P Hello header offset values.
// -------------------------------------
const (
	HdrIIHP2PCircType = HdrIIHCircType
	HdrIIHP2PSrcID    = HdrIIHSrcID
	HdrIIHP2PHoldTime = HdrIIHHoldTime
	HdrIIHP2PPDULen   = HdrIIHPDULen
	HdrIIHLclCircID   = HdrIIHP2PPDULen + 2
	HdrIIHP2PSize     = HdrIIHLclCircID
)

// ------------------------
// LSP header offset values
// ------------------------
const (
	HdrLSPPDULen   = iota
	HdrLSPLifetime = HdrLSPPDULen + 2
	HdrLSPLSPID    = HdrLSPLifetime + 2
	HdrLSPSeqNo    = HdrLSPLSPID + LSPIDLen
	HdrLSPCksum    = HdrLSPSeqNo + 4
	HdrLSPFlags    = HdrLSPCksum + 2
	HdrLSPSize     = HdrLSPFlags + 1
)

//
// LSP Flags
//
const (
	_ = 1 << iota
	_
	LSPFOverload
	LSPFMetDef
	LSPFMetDly
	LSPFMetExp
	LSPFMetErr
	LSPFPbit
)

// -------------------------
// CSNP header offset values
// -------------------------
const (
	HdrCSNPPDULen     = iota
	HdrCSNPSrcID      = HdrCSNPPDULen + 2
	HdrCSNPStartLSPID = HdrCSNPSrcID + NodeIDLen
	HdrCSNPEndLSPID   = HdrCSNPStartLSPID + LSPIDLen
	HdrCSNPSize       = HdrCSNPEndLSPID + LSPIDLen
)

// -------------------------
// PSNP header offset values
// -------------------------
const (
	HdrPSNPPDULen = iota
	HdrPSNPSrcID  = HdrCSNPPDULen + 2
	HdrPSNPSize   = HdrPSNPSrcID + NodeIDLen
)

// ======================================================
// Protocol constants for various headers and structures.
// ======================================================
const (
	LLCSSAP        = 0xfe
	LLCDSAP        = 0xfe
	LLCControl     = 3
	IDRPISIS       = 0x83
	Version        = 1
	Version2       = 1
	MaxArea        = 3
	SNPALen        = 6
	SysIDLen       = 6
	LANIDLen       = 7
	NodeIDLen      = 7
	LSPIDLen       = 8
	LSPPNodeIDOff  = 6
	LSPSegmentOff  = 7
	MaxAge         = 1200
	LSPRecvBufSize = 1492
	DefHelloInt    = 10
	DefHelloMult   = 3
	DefHelloPri    = 64
	LSPOrigBufSize = LSPRecvBufSize
)

// NLPID values
const (
	NLPIDIPv4 = 0xcc
	NLPIDIPv6 = 0x8e
)

// ====================================
// Protocol Types and Support Functions
// ====================================

// PDUType represents a PDU type
type PDUType uint8

// ---------
// PDU Types
// ---------
const (
	PDUTypeIIHLANL1 PDUType = 15
	PDUTypeIIHLANL2         = 16
	PDUTypeIIHP2P           = 17
	PDUTypeLSPL1            = 18
	PDUTypeLSPL2            = 20
	PDUTypeCSNPL1           = 24
	PDUTypeCSNPL2           = 25
	PDUTypePSNPL1           = 26
	PDUTypePSNPL2           = 27
)

func (typ PDUType) String() string {
	// XXX add nice map with strings
	return fmt.Sprintf("%d", typ)
}

// ErrUnkPDUType is returned when an unknown PDU type is encountered
type ErrUnkPDUType uint8

func (e ErrUnkPDUType) Error() string {
	return fmt.Sprintf("unknown PDU type %d", uint8(e))
}

//
// HdrLenMap map PDU type to header lengths
//
var HdrLenMap = map[PDUType]uint8{
	PDUTypeIIHLANL1: HdrCLNSSize + HdrIIHLANSize - HdrLLCSize,
	PDUTypeIIHLANL2: HdrCLNSSize + HdrIIHLANSize - HdrLLCSize,
	PDUTypeIIHP2P:   HdrCLNSSize + HdrIIHP2PSize - HdrLLCSize,
	PDUTypeLSPL1:    HdrCLNSSize + HdrLSPSize - HdrLLCSize,
	PDUTypeLSPL2:    HdrCLNSSize + HdrLSPSize - HdrLLCSize,
	PDUTypeCSNPL1:   HdrCLNSSize + HdrCSNPSize - HdrLLCSize,
	PDUTypeCSNPL2:   HdrCLNSSize + HdrCSNPSize - HdrLLCSize,
	PDUTypePSNPL1:   HdrCLNSSize + HdrPSNPSize - HdrLLCSize,
	PDUTypePSNPL2:   HdrCLNSSize + HdrPSNPSize - HdrLLCSize,
}

//
// PDULenOffMap provides the offset in the Ethernet payload of the PDU length
// field.
//
var PDULenOffMap = map[PDUType]int{
	PDUTypeIIHLANL1: HdrCLNSSize + HdrIIHPDULen,
	PDUTypeIIHLANL2: HdrCLNSSize + HdrIIHPDULen,
	PDUTypeIIHP2P:   HdrCLNSSize + HdrIIHPDULen,
	PDUTypeLSPL1:    HdrCLNSSize + HdrLSPPDULen,
	PDUTypeLSPL2:    HdrCLNSSize + HdrLSPPDULen,
	PDUTypeCSNPL1:   HdrCLNSSize + HdrCSNPPDULen,
	PDUTypeCSNPL2:   HdrCLNSSize + HdrCSNPPDULen,
	PDUTypePSNPL1:   HdrCLNSSize + HdrPSNPPDULen,
	PDUTypePSNPL2:   HdrCLNSSize + HdrPSNPPDULen,
}

//
// PDUTLVOffMap maps PDU type to the offset in the payload of the TLV data
//
var PDUTLVOffMap = map[PDUType]int{
	PDUTypeIIHLANL1: HdrCLNSSize + HdrIIHLANSize,
	PDUTypeIIHLANL2: HdrCLNSSize + HdrIIHLANSize,
	PDUTypeIIHP2P:   HdrCLNSSize + HdrIIHP2PSize,
	PDUTypeLSPL1:    HdrCLNSSize + HdrLSPSize,
	PDUTypeLSPL2:    HdrCLNSSize + HdrLSPSize,
	PDUTypeCSNPL1:   HdrCLNSSize + HdrCSNPSize,
	PDUTypeCSNPL2:   HdrCLNSSize + HdrCSNPSize,
	PDUTypePSNPL1:   HdrCLNSSize + HdrPSNPSize,
	PDUTypePSNPL2:   HdrCLNSSize + HdrPSNPSize,
}

//
// PDULevelMap maps PDU types to levels (if possible).
//
var PDULevelMap = map[PDUType]int{
	PDUTypeIIHLANL1: 1,
	PDUTypeIIHLANL2: 2,
	PDUTypeLSPL1:    1,
	PDUTypeLSPL2:    2,
	PDUTypeCSNPL1:   1,
	PDUTypeCSNPL2:   2,
	PDUTypePSNPL1:   1,
	PDUTypePSNPL2:   2,
}

//
// LevelFlag is a bitmask of enabled levels
//
type LevelFlag int

//
// Level Flags
//
const (
	L1Flag = 1 << iota
	L2Flag
)

func (lf LevelFlag) String() string {
	switch lf {
	case 0x1:
		return "L1"
	case 0x2:
		return "L2"
	case 0x3:
		return "L12"
	}
	return fmt.Sprintf("BadLevelFlag:0x%x", int(lf))
}

//
// Level is an IS-IS level
//
type Level int

func (level Level) String() string {
	return fmt.Sprintf("L%d", int(level))
}

//
// LIndex is an IS-IS level - 1
//
type LIndex int

func (lindex LIndex) String() string {
	return fmt.Sprintf("L%d", int(lindex+1))
}

// AllL1IS is the Multicast MAC to reach all level-1 IS
var AllL1IS = net.HardwareAddr{0x01, 0x80, 0xC2, 0x00, 0x00, 0x14}

// AllL2IS is the Multicast MAC to reach all level-2 IS
var AllL2IS = net.HardwareAddr{0x01, 0x80, 0xC2, 0x00, 0x00, 0x15}

// AllLxIS is lindex based array for the level respective All IS MAC address
var AllLxIS = []net.HardwareAddr{AllL1IS, AllL2IS}

// const AllES = net.ParseMac("09:00:2B:00:00:04")
// const AllIS = net.ParseMac("09:00:2B:00:00:05")

// SNPA is a MAC address in ISO talk.
type SNPA [SNPALen]byte

func (s SNPA) String() string {
	return net.HardwareAddr(s[:]).String()
}

// SystemID is a 6 octet system identifier all IS have uniq system IDs
type SystemID [SysIDLen]byte

func (s SystemID) String() string {
	return ISOString(s[:], false)
}

// NodeID identifies a node in the network graph. It is comprised of a system ID
// and a pseudo-node byte for identifying LAN Pnodes (or 0 for real nodes).
type NodeID [NodeIDLen]byte

func (s NodeID) String() string {
	return ISOString(s[:], true)
}

// LSPID identifies an LSP segment for a node in the network graph, it is
// comprised of a NodeID and a final segment octet to allow for multiple
// segments to describe an full LSP.
type LSPID [LSPIDLen]byte

func (s LSPID) String() string {
	return ISOString(s[:], false)
}

//
// ISOString returns a string representation of an ISO address (e.g., system ID
// or an area address etc), these take the form [xx.]xxxx[.xxxx.xxxx] or
// xxxx[.xxxx.xxxx][.xx] depending on whether extratail is true or not.
//
func ISOString(iso []byte, extratail bool) string {
	ilen := len(iso)
	wlen := ilen / 2
	exb := (ilen % 2) == 1
	var f string
	if !exb {
		f = strings.Repeat(".%02x%02x", wlen)[1:]
	} else if extratail {
		f = strings.Repeat(".%02x%02x", wlen+1)[1 : 9*(wlen+1)-5+1]
	} else {
		f = strings.Repeat(".%02x%02x", wlen+1)[5 : 9*(wlen+1)]
	}
	is := make([]interface{}, len(iso))
	for i, v := range iso {
		is[i] = v
	}
	return fmt.Sprintf(f, is...)
}

//
// ISODecode returns a byte slice of the hexidecimal string value given in "ISO"
// form
//
func ISODecode(isos string) (iso []byte, err error) {
	isos = strings.Replace(isos, ".", "", -1)
	iso, err = hex.DecodeString(isos)
	return
}

//
// getPDUType returns the PDU type (no-checks) from the payload
//
func getPDUType(payload []byte) PDUType {
	return PDUType(payload[HdrCLNSPDUType])
}

//
// GetPDUType returns the PDU type from the payload or an error if it is an
// unknown type.
//
func GetPDUType(payload []byte) (PDUType, error) {
	pdutype := getPDUType(payload)
	if _, ok := HdrLenMap[pdutype]; !ok {
		return pdutype, ErrUnkPDUType(pdutype)
	}
	return pdutype, nil
}

//
// GetPDULevel returns the level of the PDU type or an error if not level based.
//
func (pdutype PDUType) GetPDULevel() (int, error) {

	level, ok := PDULevelMap[pdutype]
	if !ok {
		return 0, fmt.Errorf("%s is not a level based PDU type", pdutype)
	}
	return level, nil
}

//
// ErrInvalidPacket is returned when we fail to validate the packet, this will
// be broken down into more specific cases.
//
type ErrInvalidPacket string

func (e ErrInvalidPacket) Error() string {
	return fmt.Sprintf("ErrInvalidPacket: %s", string(e))
}

// ValidatePacket validates (to an extent) a CLNS payload, and returns a correct
// version of it. (ISO10589 8.4.2.1)
// Checked Valid Items:  PDU Type, Header Length, PDU Length, Advertised
// versions(*), Advertised sizes(*) -- (*) XXX finish
func ValidatePDU(payload []byte) ([]byte, error) {
	pdutype, err := GetPDUType(payload)
	if err != nil {
		return nil, err
	}

	if HdrLenMap[pdutype] != payload[HdrCLNSLen] {
		return nil, ErrInvalidPacket(
			fmt.Sprintf("header length mismatch, expected %d got %d", HdrLenMap[pdutype], payload[HdrCLNSLen]))
	}

	off := PDULenOffMap[pdutype]
	pdulen := pkt.GetUInt16(payload[off:])
	if int(pdulen)+HdrLLCSize > len(payload) {
		return nil, ErrInvalidPacket(
			fmt.Sprintf("pdulen %d greater than payload %d", pdulen, len(payload)))
	}
	if pdulen+14 < 46 {
		return nil, ErrInvalidPacket("pdulen < 46")
	}
	if int(pdulen+HdrLLCSize) < len(payload) {
		// Don't log padded short frames
		if pdulen > 35 {
			fmt.Printf("payload %d larger than pdulen %d(+3) trimming\n",
				len(payload), pdulen)
		}
		payload = payload[:pdulen+HdrLLCSize]
	}
	return payload, nil
}
