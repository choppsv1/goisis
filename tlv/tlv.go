package tlv

import (
	"fmt"
)

// TLV - Type-Length-Value object
type TLV interface {
	Type() (int, error)
	Length() (int, error)
	Value() ([]byte, error)
}

// ErrNoSpace is returns from TLV adding routines when there is not enough space
// to continue.
type ErrNoSpace struct {
	required, capacity int
}

func (e ErrNoSpace) Error() string {
	return fmt.Sprintf("Not enough space (offer: %d) for TLV (ask: %d)", e.capacity, e.required)
}

// GetTLV returns type. length and value of a TLV or an error if we can't
func GetTLV(t TLV) (int, int, []byte, error) {
	var typ, length int
	var value []byte
	var err error

	if typ, err = t.Type(); err != nil {
		return -1, -1, nil, err
	}
	if length, err = t.Length(); err != nil {
		return -1, -1, nil, err
	}
	if value, err = t.Value(); err != nil {
		return -1, -1, nil, err
	}

	return typ, length, value, nil
}
