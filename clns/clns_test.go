package clns

import (
	"bytes"
	"testing"
)

func TestISOString(t *testing.T) {
	addr := []byte{0, 1, 2, 3, 4, 5, 6}

	rv := ISOString(addr, false)
	if "00.0102.0304.0506" != rv {
		t.Error(rv)
	}
	rv = ISOString(addr, true)
	if "0001.0203.0405.06" != rv {
		t.Error(rv)
	}
	rv = ISOString(addr[1:], false)
	if "0102.0304.0506" != rv {
		t.Error(rv)
	}
	rv = ISOString(addr[:5], false)
	if "00.0102.0304" != rv {
		t.Error(rv)
	}
	rv = ISOString(addr[:5], true)
	if "0001.0203.04" != rv {
		t.Error(rv)
	}
	rv = ISOString(addr[1:5], false)
	if "0102.0304" != rv {
		t.Error(rv)
	}
	rv = ISOString(addr[:3], false)
	if "00.0102" != rv {
		t.Error(rv)
	}
	rv = ISOString(addr[:3], true)
	if "0001.02" != rv {
		t.Error(rv)
	}
	rv = ISOString(addr[1:3], false)
	if "0102" != rv {
		t.Error(rv)
	}
	rv = ISOString(addr[1:3], true)
	if "0102" != rv {
		t.Error(rv)
	}
	rv = ISOString(addr[:1], false)
	if "00" != rv {
		t.Error(rv)
	}
	rv = ISOString(addr[:1], true)
	if "00" != rv {
		t.Error(rv)
	}
}

func TestISODecode(t *testing.T) {
	addr := []byte{0, 1, 2, 3, 4, 5, 6}

	tval := addr
	rv, err := ISODecode("00.0102.0304.0506")
	if !bytes.Equal(rv, tval) || err != nil {
		t.Error(tval)
	}
	tval = addr
	rv, err = ISODecode("0001.0203.0405.06")
	if !bytes.Equal(rv, tval) || err != nil {
		t.Error(tval)
	}
	tval = addr[1:]
	rv, err = ISODecode("0102.0304.0506")
	if !bytes.Equal(rv, tval) || err != nil {
		t.Error(tval)
	}
	tval = addr[:5]
	rv, err = ISODecode("00.0102.0304")
	if !bytes.Equal(rv, tval) || err != nil {
		t.Error(tval)
	}
	tval = addr[:5]
	rv, err = ISODecode("0001.0203.04")
	if !bytes.Equal(rv, tval) || err != nil {
		t.Error(tval)
	}
	tval = addr[1:5]
	rv, err = ISODecode("0102.0304")
	if !bytes.Equal(rv, tval) || err != nil {
		t.Error(tval)
	}
	tval = addr[:3]
	rv, err = ISODecode("00.0102")
	if !bytes.Equal(rv, tval) || err != nil {
		t.Error(tval)
	}
	tval = addr[:3]
	rv, err = ISODecode("0001.02")
	if !bytes.Equal(rv, tval) || err != nil {
		t.Error(tval)
	}
	tval = addr[1:3]
	rv, err = ISODecode("0102")
	if !bytes.Equal(rv, tval) || err != nil {
		t.Error(tval)
	}
	tval = addr[1:3]
	rv, err = ISODecode("0102")
	if !bytes.Equal(rv, tval) || err != nil {
		t.Error(tval)
	}
	tval = addr[:1]
	rv, err = ISODecode("00")
	if !bytes.Equal(rv, tval) || err != nil {
		t.Error(tval)
	}
	tval = addr[:1]
	rv, err = ISODecode("00")
	if !bytes.Equal(rv, tval) || err != nil {
		t.Error(tval)
	}
}
