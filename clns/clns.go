package clns

import (
	"encoding/hex"
	"fmt"
	"github.com/choppsv1/goisis/ether"
	"github.com/choppsv1/goisis/pkt"
	"net"
	"strings"
	"time"
)

// ===============================
// Packet Headers (offset values).
// ===============================

// ------------------------------------
// ISO 10589 CLNS header offset values.
// ------------------------------------
const (
	HdrCLNSIDRP = iota
	HdrCLNSLen
	HdrCLNSVer
	HdrCLNSSysIDLen
	HdrCLNSPDUType
	HdrCLNSVer2
	HdrCLNSResv
	HdrCLNSMaxArea
	HdrCLNSSize
)

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
// LSPFlags are defined in ISO10589:2002 XXX
//
type LSPFlags uint8

// The LSP Flags
const (
	_ LSPFlags = 1 << iota
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
	LLCSAP         = 0xfefe
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
	MaxAgeDur      = time.Duration(1200) * time.Second
	ZeroMaxAge     = 60
	ZeroMaxAgeDur  = time.Duration(60) * time.Second
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

// Level is an IS-IS level
type Level uint8

const (
	Level1 Level = 1
	Level2       = 2
)

func (l Level) String() string {
	return fmt.Sprintf("L%d", int(l))
}

func (l Level) ToIndex() LIndex {
	if l < 1 || l > 2 {
		panic(fmt.Sprintf("Invalid l %d", l))
	}
	return LIndex(l - 1)
}

func (l Level) ToFlag() LevelFlag {
	return LevelToFlag(l)
}

type LevelFlag uint8

const (
	L1Flag LevelFlag = 1 << iota
	L2Flag
)

func LevelToFlag(l Level) LevelFlag {
	return LevelFlag(1 << (l - 1))
}

func (lf LevelFlag) IsLevelEnabled(l Level) bool {
	return (LevelToFlag(l) & lf) != 0
}

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

// LIndex is an IS-IS level - 1
type LIndex int

func (li LIndex) String() string {
	return fmt.Sprintf("L%d", int(li+1))
}

// ToLevel returns the lindex as a Level.
func (li LIndex) ToLevel() Level {
	return Level(li + 1)
}

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

var PDUTypeDesc = map[PDUType]string{
	PDUTypeIIHLANL1: "PDUTypeIIHLANL1",
	PDUTypeIIHLANL2: "PDUTypeIIHLANL2",
	PDUTypeIIHP2P:   "PDUTypeIIHP2P",
	PDUTypeLSPL1:    "PDUTypeLSPL1",
	PDUTypeLSPL2:    "PDUTypeLSPL2",
	PDUTypeCSNPL1:   "PDUTypeCSNPL1",
	PDUTypeCSNPL2:   "PDUTypeCSNPL2",
	PDUTypePSNPL1:   "PDUTypePSNPL1",
	PDUTypePSNPL2:   "PDUTypePSNPL2",
}

func (typ PDUType) String() string {
	// XXX add nice map with strings
	if desc, ok := PDUTypeDesc[typ]; ok {
		return fmt.Sprintf("%s", desc)
	} else {
		return fmt.Sprintf("%d", typ)
	}
}

// ErrNonISISSAP indicates the frame isn't an IS-IS frame
type ErrNonISISSAP uint16

func (e ErrNonISISSAP) Error() string {
	return fmt.Sprintf("Wrong ISIS LLC SAP %#04v", uint16(e))
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
// SrcIDOffMap provides the offset in the Ethernet payload of the SrcID
// field.
//
var SrcIDOffMap = map[PDUType]uint{
	PDUTypeIIHLANL1: HdrCLNSSize + HdrIIHSrcID,
	PDUTypeIIHLANL2: HdrCLNSSize + HdrIIHSrcID,
	PDUTypeIIHP2P:   HdrCLNSSize + HdrIIHSrcID,
	PDUTypeCSNPL1:   HdrCLNSSize + HdrCSNPSrcID,
	PDUTypeCSNPL2:   HdrCLNSSize + HdrCSNPSrcID,
	PDUTypePSNPL1:   HdrCLNSSize + HdrPSNPSrcID,
	PDUTypePSNPL2:   HdrCLNSSize + HdrPSNPSrcID,
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
var PDULevelMap = map[PDUType]Level{
	PDUTypeIIHLANL1: Level(1),
	PDUTypeIIHLANL2: Level(2),
	PDUTypeLSPL1:    Level(1),
	PDUTypeLSPL2:    Level(2),
	PDUTypeCSNPL1:   Level(1),
	PDUTypeCSNPL2:   Level(2),
	PDUTypePSNPL1:   Level(1),
	PDUTypePSNPL2:   Level(2),
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

func HWToSNPA(h net.HardwareAddr) (snpa SNPA) {
	copy(snpa[:], h)
	return
}

// SystemID is a 6 octet system identifier all IS have uniq system IDs
type SystemID [SysIDLen]byte

func (s SystemID) String() string {
	return ISOString(s[:], false)
}

func GetSrcID(payload []byte) (sysid SystemID) {
	off, ok := SrcIDOffMap[getPDUType(payload)]
	if !ok {
		panic("Invalid payload to GetSrcID")
	}
	copy(sysid[:], payload[off:])
	return
}

// NodeID identifies a node in the network graph. It is comprised of a system ID
// and a pseudo-node byte for identifying LAN Pnodes (or 0 for real nodes).
type NodeID [NodeIDLen]byte

func (n NodeID) String() string {
	return ISOString(n[:], true)
}

// LSPID identifies an LSP segment for a node in the network graph, it is
// comprised of a NodeID and a final segment octet to allow for multiple
// segments to describe an full LSP.
type LSPID [LSPIDLen]byte

func (l LSPID) String() string {
	return ISOString(l[:LSPIDLen], true)
}

// LSPIDString prints a LSPID given a generic byte slice.
func LSPIDString(lspid []byte) string {
	return ISOString(lspid[:LSPIDLen], true)
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
// ISOEncode returns a byte slice of the hexidecimal string value given in "ISO"
// form
//
func ISOEncode(isos string) (iso []byte, err error) {
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
func (pdutype PDUType) GetPDULevel() (Level, error) {

	l, ok := PDULevelMap[pdutype]
	if !ok {
		return 0, fmt.Errorf("%s is not a level based PDU type", pdutype)
	}
	return l, nil
}

//
// GetPDULIndex returns the level index of the PDU type assumes the type is valid
//
func (pdutype PDUType) GetPDULIndex() LIndex {

	return LIndex(PDULevelMap[pdutype] - 1)
}

//
// ErrInvalidPacket is returned when we fail to validate the packet, this will
// be broken down into more specific cases.
//
type ErrInvalidPacket string

func (e ErrInvalidPacket) Error() string {
	return fmt.Sprintf("ErrInvalidPacket: %s", string(e))
}

// ValidatePDU validates (to an extent) a CLNS payload, and returns a correct
// version of it. (ISO10589 8.4.2.1.[ab] and 7.3.15.{1,2}.a: 1* 2, 3, 4, 5)
// Checked Valid Items:  PDU Type, Header Length, PDU Length, Advertised
// versions(*), Advertised sizes -- (*) XXX finish
func ValidatePDU(llc, payload []byte, istype, ctype LevelFlag) ([]byte, PDUType, error) {
	// Should not be dependent on circuit type -- move to CLNS
	sap := pkt.GetUInt16(llc[0:2])
	if sap != LLCSAP {
		return nil, 0, ErrNonISISSAP(sap)
	}

	pdutype, err := GetPDUType(payload)
	if err != nil {
		return nil, pdutype, err
	}

	if HdrLenMap[pdutype] != payload[HdrCLNSLen] {
		return nil, pdutype, ErrInvalidPacket(
			fmt.Sprintf("header length mismatch, expected %d got %d", HdrLenMap[pdutype], payload[HdrCLNSLen]))
	}

	off := PDULenOffMap[pdutype]
	pdulen := pkt.GetUInt16(payload[off:])
	if int(pdulen) > len(payload) {
		return nil, pdutype, ErrInvalidPacket(
			fmt.Sprintf("pdulen %d greater than payload %d", pdulen, len(payload)))
	}
	if pdulen+ether.HdrLLCSize+ether.HdrEthSize < 46 {
		return nil, pdutype, ErrInvalidPacket("ether < 46")
	}
	if int(pdulen) < len(payload) {
		// Don't log padded short frames
		if pdulen > 35 {
			fmt.Printf("payload %d larger than pdulen %d(+3) trimming\n",
				len(payload), pdulen)
		}
		payload = payload[:pdulen]
	}

	l, ok := PDULevelMap[pdutype]
	if ok {
		// P2PHello won't have a level, don't fail
		// ISO10589: 7.3.15.1: 2
		if !istype.IsLevelEnabled(l) {
			return nil, pdutype, nil
		}
		// ISO10589: 7.3.15.1: 3
		if !ctype.IsLevelEnabled(l) {
			return nil, pdutype, nil
		}
	}

	// ISO10589: 7.3.15.1: 4
	sysidlen := payload[HdrCLNSSysIDLen]
	if sysidlen != 0 && sysidlen != 6 {
		return nil, pdutype, ErrInvalidPacket(
			fmt.Sprintf("TRAP iDFieldLengthMismtach: %d", sysidlen))
	}
	// ISO10589 7.3.15.1: 5)
	maxarea := payload[HdrCLNSMaxArea]
	if maxarea != 0 && maxarea != 3 {
		return nil, pdutype, ErrInvalidPacket(
			fmt.Sprintf("TRAP maximumAreaAddressesMismatch %d", maxarea))
	}

	return payload, pdutype, nil
}
