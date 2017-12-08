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

// GetDst returns the destination MAC of the Ethernet frame.
func (p Frame) GetDst() net.HardwareAddr {
	return net.HardwareAddr(p[0:6])
}

// SetDst sets the destination MAC of the Ethernet frame.
func (p Frame) SetDst(addr net.HardwareAddr) {
	copy(p[HdrEthDest:], addr[0:6])
}

// GetSrc returns the source MAC address of the Ethernet frame.
func (p Frame) GetSrc() net.HardwareAddr {
	return net.HardwareAddr(p[6:12])
}

// SetSrc returns the source MAC address of the Ethernet frame.
func (p Frame) SetSrc(addr net.HardwareAddr) {
	copy(p[HdrEthSrc:], addr[0:6])
}

// GetTypeLen returns the length field (type) of the Ethernet frame.
func (p Frame) GetTypeLen() int {
	return int(p[12])<<8 | int(p[13])
}

// SetTypeLen returns the length field (type) of the Ethernet frame.
func (p Frame) SetTypeLen(typlen int) {
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
	etype := p.GetTypeLen()
	if len(payload) < 46 {
		return nil, ErrInvalidFrame("payload < 46")
	}

	if ours := ourSNPA[MACKey(p.GetSrc())]; ours {
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
