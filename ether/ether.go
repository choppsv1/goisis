package ether

import (
	"fmt"
	"net"
)

// ------------------------------------
// 802.3 Ethernet header offset values.
// ------------------------------------
const (
	HdrEthDest = 0
	HdrEthSrc  = HdrEthDest + 6
	HdrEthLen  = HdrEthSrc + 6
	HdrEthSize = HdrEthLen + 2
)

// ------------------------------

// ------------------------------
const ()

// Frame represents an Ethernet frame
type Frame []byte

type MAC [6]byte

// MACKey returns a MAC key (array) from a slice representing a MAC
func MACKey(addr net.HardwareAddr) (mac MAC) {
	copy(mac[:], addr)
	return
}

// GetEtherDest returns the destination MAC of the Ethernet frame.
func (p Frame) GetEtherDest() net.HardwareAddr {
	return net.HardwareAddr(p[0:6])
}

// SetEtherDest sets the destination MAC of the Ethernet frame.
func (p Frame) SetEtherDest(addr net.HardwareAddr) {
	copy(p[HdrEthDest:], addr[0:6])
}

// GetEtherSrc returns the source MAC address of the Ethernet frame.
func (p Frame) GetEtherSrc() net.HardwareAddr {
	return net.HardwareAddr(p[6:12])
}

// SetEtherSrc returns the source MAC address of the Ethernet frame.
func (p Frame) SetEtherSrc(addr net.HardwareAddr) {
	copy(p[HdrEthSrc:], addr[0:6])
}

// GetEtherTypeLen returns the length field (type) of the Ethernet frame.
func (p Frame) GetEtherTypeLen() int {
	return int(p[12])<<8 | int(p[13])
}

// SetEtherTypeLen returns the length field (type) of the Ethernet frame.
func (p Frame) SetEtherTypeLen(typlen int) {
	p[12] = byte(typlen >> 8)
	p[13] = byte(typlen & 0xFF)
}

// ErrInvalidFrame indicates that the received Ethernet frame was invalid in
// some way.
type ErrInvalidFrame string

func (e ErrInvalidFrame) Error() string {
	return fmt.Sprintf("%s", string(e))
}

// ErrOurFrame is returned if we are dropping a frame we received from ourselves
type ErrOurFrame bool

func (e ErrOurFrame) Error() string {
	return fmt.Sprintf("received a frame with our src mac")
}

// ValidateFrame checks the Ethernet values and return the payload or an error
// if something is incorrect.
func (p Frame) ValidateFrame(ourSNPA map[MAC]bool) ([]byte, error) {
	payload := p[HdrEthSize:]
	etype := p.GetEtherTypeLen()
	if len(payload) < 46 {
		return nil, ErrInvalidFrame("payload < 46")
	}

	if ours := ourSNPA[MACKey(p.GetEtherSrc())]; ours {
		return nil, ErrOurFrame(true)
	}

	if etype > 1514 && etype != 0x8870 {
		// Drop non-LLC that aren't jumbo frames
		return nil, nil
	}
	if etype != len(payload) {
		return nil, ErrInvalidFrame(fmt.Sprintf("invalid ethernet frame llc len (%d) and payload (%d) mismatch", etype, len(payload)))
	}
	return payload, nil
}
