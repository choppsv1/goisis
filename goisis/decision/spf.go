// -*- coding: utf-8 -*-
//
// December 28 2018, Christian E. Hopps <chopps@gmail.com>

// The IS-IS decision process (SPF)
package spf

import (
	"github.com/choppsv1/goisis/tlv"
)

type Segment struct {
	hdr  []byte
	tlvs map[tlv.Type][]tlv.Data
}

type LSP {
	tlvs map[tlv.Type][]tlv.Data
