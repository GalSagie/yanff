// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"

	"github.com/intel-go/yanff/test/stability/test_cksum/common"
)

// Main function for constructing packet processing graph.
func main() {
	var inport, outport uint
	var hwol bool

	flag.BoolVar(&hwol, "hwol", false, "Use Hardware offloading for TX checksums calculation")
	flag.UintVar(&inport, "inport", 0, "Input port number")
	flag.UintVar(&outport, "outport", 1, "Output port number")

	// Init YANFF system
	flow.SystemInit(16)

	// Receive packets from zero port. Receive queue will be added automatically.
	inputFlow := flow.SetReceiver(uint8(inport))
	flow.SetHandler(inputFlow, fixPacket, nil)
	flow.SetSender(inputFlow, uint8(outport))

	// Begin to process packets.
	flow.SystemStart()
}

func fixPacket(pkt *packet.Packet, context flow.UserContext) {
	if !common.CheckPacketChecksums(pkt) {
		println("TEST FAILED")
	}

	offset := pkt.ParseL4Data()
	if offset < 0 {
		println("ParseL4 returned negative value", offset)
		println("TEST FAILED")
		return
	}

	ptr := (*common.Packetdata)(pkt.Data)
	if ptr.F2 != 0 {
		fmt.Printf("Bad data found in the packet: %x\n", ptr.F2)
		println("TEST FAILED")
		return
	}

	ptr.F2 = ptr.F1

	common.CalculateChecksum(pkt)
}