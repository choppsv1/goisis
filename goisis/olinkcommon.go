// -*- coding: utf-8 -*-
//
// November 21 2018, Christian Hopps <chopps@gmail.com>
//
package main

// // ----------------------------------------------------------------
// // LinkCommon collects common functionality from all types of links
// // ----------------------------------------------------------------
// type LinkCommon struct {
// 	link     Link
// 	intf     *net.Interface
// 	sock     raw.IntfSocket
// 	sxxFlags [2][2]FlagSet
// 	v4addrs  []net.IPNet
// 	v6addrs  []net.IPNet
// 	inpkt    chan<- *RecvFrame
// 	outpkt   chan []byte
// 	quit     <-chan bool
// }

// func NewLink() {
// 	common := &LinkCommon{
// 		link: link,
// 		sxxFlags: [2][2]FlagSet{
// 			{NewFlagSet(), NewFlagSet()},
// 			{NewFlagSet(), NewFlagSet()},
// 		},
// 		inpkt:  inpkt,
// 		outpkt: make(chan []byte),
// 		quit:   quit,
// 	}

// 	if common.intf, err = net.InterfaceByName(ifname); err != nil {
// 		fmt.Fprintf(os.Stderr, "Error InterfaceByName: %s\n", err)
// 		return nil, err
// 	}

// 	var addrs []net.Addr
// 	if addrs, err = common.intf.Addrs(); err != nil {
// 		fmt.Fprintf(os.Stderr, "Error intf.Addrs: %s\n", err)
// 		return nil, err
// 	}
// 	for _, addr := range addrs {
// 		ipnet := addr.(*net.IPNet)
// 		ipv4 := ipnet.IP.To4()
// 		if ipv4 != nil {
// 			ipnet.IP = ipv4
// 			common.v4addrs = append(common.v4addrs, *ipnet)
// 		} else {
// 			common.v6addrs = append(common.v6addrs, *ipnet)
// 		}
// 	}

// 	// Get raw socket connection for interface send/receive
// 	if common.sock, err = raw.NewInterfaceSocket(common.intf.Name); err != nil {
// 		fmt.Fprintf(os.Stderr, "Error NewInterfaceSocket: %s\n", err)
// 		return nil, err
// 	}
// 	// XXX Update Process: signal DIS change

// 	// IS-IS BPF filter
// 	filter, err := bpf.Assemble([]bpf.Instruction{
// 		// 0: Load 2 bytes from offset 12 (ethertype)
// 		bpf.LoadAbsolute{Off: 12, Size: 2},
// 		// 1: Jump fwd + 1 if 0x8870 (jumbo) otherwise fwd + 0 (continue)
// 		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8870, SkipTrue: 1},
// 		// 2: Jump fwd + 3 if > 1500 (drop non-IEEE 802.2 LLC) otherwise fwd + 0 (continue)
// 		bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: 1500, SkipTrue: 3},
// 		// 3: Load 2 bytes from offset 14 (llc src, dst)
// 		bpf.LoadAbsolute{Off: 14, Size: 2},
// 		// 4: Jump fwd + 0 if 0xfefe (keep) otherwise fwd + 1 (drop)
// 		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0xfefe, SkipTrue: 1},
// 		// 5: Keep
// 		bpf.RetConstant{Val: 0xffff},
// 		// 6: Drop
// 		bpf.RetConstant{Val: 0},
// 	})
// 	if err != nil {
// 		fmt.Fprintf(os.Stderr, "Error bpf.Assemble: %s\n", err)
// 		return nil, err
// 	}
// }

// func (l *LinkCommon) SetFlag(seg *LSPSegment, flag SxxFlag) {
// 	l.sxxFlags[seg.lindex][flag].Add(seg.lspid)
// }

// func (l *LinkCommon) ClearFlag(seg *LSPSegment, flag SxxFlag) {
// 	l.sxxFlags[seg.lindex][flag].Remove(seg.lspid)
// }

// func (l *LinkCommon) GetFlags(lindex uint8, flag SxxFlag) FlagSet {
// 	return l.sxxFlags[lindex][flag]
// }
