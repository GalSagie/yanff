// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/md5"
	"flag"
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
	"sync"
	"sync/atomic"
	"unsafe"
)

// test-merge-part1:
// This part of test generates packets on ports 0 and 1, receives packets
// on 0 port. Packets generated on 0 port has IPv4 source addr IPV4ADDR_1,
// and those generated on 1 port has ipv4 source addr IPV4ADDR_2. For each packet
// sender calculates md5 hash sum from all headers and write it to packet.Data.
// When packet is received, hash is recomputed and checked if it is equal to value
// in the packet. Test also calculates sent/received ratios, number of broken
// packets and prints it when a predefined number of packets is received.
//
// test-merge-part2:
// This part of test receives packets on 0 and 1 ports, merges flows
// and send result flow to 0 port.

const (
	TOTAL_PACKETS = 100000000
)

var (
	// Payload is 16 byte md5 hash sum of headers
	PAYLOAD_SIZE uint   = 16
	SPEED        uint64 = 1000
	PASSED_LIMIT uint64 = 85

	sentPacketsGroup1 uint64 = 0
	sentPacketsGroup2 uint64 = 0
	recvPacketsGroup1 uint64 = 0
	recvPacketsGroup2 uint64 = 0
	recvPackets       uint64 = 0
	brokenPackets     uint64 = 0

	// Usually when writing multibyte fields to packet, we should make
	// sure that byte order in packet buffer is correct and swap bytes if needed.
	// Here for testing purposes we use addresses with bytes swapped by hand.
	IPV4ADDR_1 uint32 = 0x0100007f // 127.0.0.1
	IPV4ADDR_2 uint32 = 0x05090980 // 128.9.9.5

	testDoneEvent *sync.Cond = nil

	outport1 uint
	outport2 uint
	inport  uint
)

func main() {
	flag.Uint64Var(&PASSED_LIMIT, "PASSED_LIMIT", PASSED_LIMIT, "received/sent minimum ratio to pass test")
	flag.Uint64Var(&SPEED, "SPEED", SPEED, "speed of 1 and 2 generators, Pkts/s")
	flag.UintVar(&outport1, "outport1", 0, "port for 1st sender")
	flag.UintVar(&outport2, "outport2", 1, "port for 2nd sender")
	flag.UintVar(&inport, "inport", 0, "port for receiver")

	flow.SystemInit(16)

	var m sync.Mutex
	testDoneEvent = sync.NewCond(&m)

	firstFlow := flow.SetGenerator(generatePacketGroup1, SPEED, nil)
	flow.SetSender(firstFlow, uint8(outport1))

	// Create second packet flow
	secondFlow := flow.SetGenerator(generatePacketGroup2, SPEED, nil)
	flow.SetSender(secondFlow, uint8(outport2))

	// Create receiving flow and set a checking function for it
	inputFlow := flow.SetReceiver(uint8(inport))

	flow.SetHandler(inputFlow, checkPackets, nil)
	flow.SetStopper(inputFlow)

	// Start pipeline
	go flow.SystemStart()

	// Wait for enough packets to arrive
	testDoneEvent.L.Lock()
	testDoneEvent.Wait()
	testDoneEvent.L.Unlock()

	// Compose statistics
	sent1 := atomic.LoadUint64(&sentPacketsGroup1)
	sent2 := atomic.LoadUint64(&sentPacketsGroup2)
	sent := sent1 + sent2
	recv1 := atomic.LoadUint64(&recvPacketsGroup1)
	recv2 := atomic.LoadUint64(&recvPacketsGroup2)
	received := recv1 + recv2
	// Proportions of 1 and 2 packet in received flow
	p1 := int(recv1 * 100 / received)
	p2 := int(recv2 * 100 / received)
	broken := atomic.LoadUint64(&brokenPackets)

	// Print report
	println("Sent", sent, "packets")
	println("Received", received, "packets")
	println("Group1 ratio =", recv1*100/sent1, "%")
	println("Group2 ratio =", recv2*100/sent2, "%")

	println("Group1 proportion in received flow =", p1, "%")
	println("Group2 proportion in received flow =", p2, "%")

	println("Broken = ", broken, "packets")

	// Test is passed, if p1 and p2 do not differ too much: |p1-p2| < 4%
	// and enough packets received back
	if (p1-p2 < 4 || p2-p1 < 4) && received*100/sent > PASSED_LIMIT {
		println("TEST PASSED")
	} else {
		println("TEST FAILED")
	}
}

func generatePacketGroup1(pkt *packet.Packet, context flow.UserContext) {
	packet.InitEmptyEtherIPv4UDPPacket(pkt, PAYLOAD_SIZE)
	if pkt == nil {
		panic("Failed to create new packet")
	}
	pkt.IPv4.SrcAddr = IPV4ADDR_1

	// Extract headers of packet
	headerSize := uintptr(pkt.Data) - pkt.Unparsed
	hdrs := (*[1000]byte)(unsafe.Pointer(pkt.Unparsed))[0:headerSize]
	ptr := (*PacketData)(pkt.Data)
	ptr.HdrsMD5 = md5.Sum(hdrs)

	atomic.AddUint64(&sentPacketsGroup1, 1)
}

func generatePacketGroup2(pkt *packet.Packet, context flow.UserContext) {
	packet.InitEmptyEtherIPv4UDPPacket(pkt, PAYLOAD_SIZE)
	if pkt == nil {
		panic("Failed to create new packet")
	}
	pkt.IPv4.SrcAddr = IPV4ADDR_2

	// Extract headers of packet
	headerSize := uintptr(pkt.Data) - pkt.Unparsed
	hdrs := (*[1000]byte)(unsafe.Pointer(pkt.Unparsed))[0:headerSize]
	ptr := (*PacketData)(pkt.Data)
	ptr.HdrsMD5 = md5.Sum(hdrs)

	atomic.AddUint64(&sentPacketsGroup2, 1)
}

// Count and check packets in received flow
func checkPackets(pkt *packet.Packet, context flow.UserContext) {
	recvCount := atomic.AddUint64(&recvPackets, 1)

	offset := pkt.ParseL4Data()
	if offset < 0 {
		println("ParseL4Data returned negative value", offset)
		// On 2nd port can be received packets, which are not generated by this example
		// They cannot be parsed due to unknown protocols, skip them
	} else {
		ptr := (*PacketData)(pkt.Data)

		// Recompute hash to check how many packets are valid
		headerSize := uintptr(pkt.Data) - pkt.Unparsed
		hdrs := (*[1000]byte)(unsafe.Pointer(pkt.Unparsed))[0:headerSize]
		hash := md5.Sum(hdrs)

		if hash != ptr.HdrsMD5 {
			// Packet is broken
			atomic.AddUint64(&brokenPackets, 1)
			return
		}
		if pkt.IPv4.SrcAddr == IPV4ADDR_1 {
			atomic.AddUint64(&recvPacketsGroup1, 1)
		} else if pkt.IPv4.SrcAddr == IPV4ADDR_2 {
			atomic.AddUint64(&recvPacketsGroup2, 1)
		} else {
			println("Packet Ipv4 src addr does not match addr1 or addr2")
		}
	}

	if recvCount >= TOTAL_PACKETS {
		testDoneEvent.Signal()
	}
}

type PacketData struct {
	HdrsMD5 [16]byte
}
