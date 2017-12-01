package pkt

// ==========================================================
// Pkt Functions dealing with manipulating binary packet data
// ==========================================================

// GetUInt16 extracts a network order encoded uin16 from the packet buffer at
// the given offset.
func GetUInt16(p []byte) uint16 {
	data := uint16(p[0]) << 8
	data |= uint16(p[1])
	return data
}

// PutUInt16 encodes a uin16 value into the the packet at the given offset in
// network order.
func PutUInt16(p []byte, data uint16) {
	p[0] = uint8((data >> 8) & 0xFF)
	p[1] = uint8(data & 0xFF)
}

// GetUInt32 extracts a network order encoded uin16 from the packet buffer at
// the given offset.
func GetUInt32(p []byte) uint32 {
	data := uint32(p[0]) << 24
	data |= uint32(p[1]) << 16
	data |= uint32(p[2]) << 8
	data |= uint32(p[3])
	return data
}

// PutUInt32 encodes a uin32 value into the the packet at the given offset in
// network order.
func PutUint32(p []byte, data uint32) {
	p[0] = uint8((data >> 24) & 0xFF)
	p[1] = uint8((data >> 16) & 0xFF)
	p[2] = uint8((data >> 8) & 0xFF)
	p[3] = uint8(data & 0xFF)
}
