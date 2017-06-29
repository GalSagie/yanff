// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package common

import (
	"fmt"
	"unsafe"

	"github.com/intel-go/yanff/packet"
)

type Packetdata struct {
	F1, F2 uint64
}

func CheckPacketChecksums(p *packet.Packet) bool {
	status := false

	if p.Ether.EtherType == packet.SwapBytesUint16(packet.IPV4Number) {
		l3status := true
		if p.IPv4.HdrChecksum != CalculateIPv4Checksum(p) {
			println("IPv4 checksum mismatch")
			l3status = false
		}

		if p.IPv4.NextProtoID == packet.UDPNumber {
			csum := CalculateIPv4UDPChecksum(p)
			if p.UDP.DgramCksum != csum {
				println("IPv4 UDP datagram checksum mismatch", p.UDP.DgramCksum, "should be", csum)
			} else {
				status = l3status
			}
		} else if p.IPv4.NextProtoID == packet.TCPNumber {
			csum := CalculateIPv4TCPChecksum(p)
			if p.TCP.Cksum != csum {
				println("IPv4 TCP checksum mismatch", p.TCP.Cksum, "should be", csum)
			} else {
				status = l3status
			}
		} else {
			println("Unknown IPv4 protocol number", p.IPv4.NextProtoID)
		}
	} else if p.Ether.EtherType == packet.SwapBytesUint16(packet.IPV6Number) {
		if p.IPv6.Proto == packet.UDPNumber {
			csum := CalculateIPv6UDPChecksum(p)
			if p.UDP.DgramCksum != csum {
				println("IPv6 UDP datagram checksum mismatch:", p.UDP.DgramCksum, "should be", csum)
			} else {
				status = true
			}
		} else if p.IPv6.Proto == packet.TCPNumber {
			csum := CalculateIPv6TCPChecksum(p)
			if p.TCP.Cksum != csum {
				println("IPv6 TCP datagram checksum mismatch", p.TCP.Cksum, "should be", csum)
			} else {
				status = true
			}
		} else {
			println("Unknown IPv6 protocol number", p.IPv6.Proto)
		}
	} else {
		println("Unknown packet EtherType", p.Ether.EtherType)
	}

	return status
}

// Calculates checksum of memory for a given pointer. Length and
// offset are in bytes. Offset is signed, so negative offset is
// possible. Checksum is calculated in uint16 words. Returned is
// checksum with carry, so carry should be added and value negated for
// use as network checksum.
func calculateDataChecksum(ptr unsafe.Pointer, length, offset int) uint32 {
	var sum uint32 = 0
	uptr := uintptr(ptr) + uintptr(offset)

	slice := (*[1 << 30]uint16)(unsafe.Pointer(uptr))[0: length / 2]
	for i := range slice {
		sum += uint32(packet.SwapBytesUint16(slice[i]))
		fmt.Printf("data = 0x%04x, sum = 0x%x\n", uint32(packet.SwapBytesUint16(slice[i])), sum)
	}

	if length & 1 != 0 {
		sum += uint32(*(*byte)(unsafe.Pointer(uptr + uintptr(length - 1))) << 8)
	}

	return sum
}

func fixChecksum(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	return uint16(^sum)
}

func CalculateIPv4Checksum(p *packet.Packet) uint16 {
	var sum uint32
	hdr := p.IPv4

	sum = uint32(hdr.VersionIhl << 8) + uint32(hdr.TypeOfService) +
		uint32(packet.SwapBytesUint16(hdr.TotalLength)) +
		uint32(packet.SwapBytesUint16(hdr.PacketID)) +
		uint32(packet.SwapBytesUint16(hdr.FragmentOffset)) +
		uint32(hdr.TimeToLive << 8) + uint32(hdr.NextProtoID) +
		uint32(packet.SwapBytesUint16(uint16(hdr.SrcAddr >> 16))) +
        uint32(packet.SwapBytesUint16(uint16(hdr.SrcAddr))) +
		uint32(packet.SwapBytesUint16(uint16(hdr.DstAddr >> 16))) +
		uint32(packet.SwapBytesUint16(uint16(hdr.DstAddr)))

	return fixChecksum(sum)
}

func calculateIPv4AddrChecksum(hdr *packet.IPv4Hdr) uint32 {
	return uint32(packet.SwapBytesUint16(uint16(hdr.SrcAddr >> 16))) +
		uint32(packet.SwapBytesUint16(uint16(hdr.SrcAddr))) +
		uint32(packet.SwapBytesUint16(uint16(hdr.DstAddr >> 16))) +
		uint32(packet.SwapBytesUint16(uint16(hdr.DstAddr)))
}

func CalculateIPv4UDPChecksum(p *packet.Packet) uint16 {
	hdr := p.IPv4
	udp := p.UDP
	dataLength := packet.SwapBytesUint16(hdr.TotalLength) - packet.IPv4MinLen

	sum := calculateDataChecksum(p.Data, int(dataLength - packet.UDPLen), 0)

	sum += calculateIPv4AddrChecksum(hdr) +
		uint32(hdr.NextProtoID) +
		uint32(hdr.TotalLength) +
		uint32(packet.SwapBytesUint16(udp.SrcPort)) +
		uint32(packet.SwapBytesUint16(udp.DstPort)) +
		uint32(dataLength - packet.UDPLen)

	fmt.Printf("0x%04x + 0x%04x + 0x%04x + 0x%04x + 0x%04x + 0x%04x = %x\n",
		uint32(packet.SwapBytesUint16(uint16(hdr.SrcAddr >> 16))),
		uint32(packet.SwapBytesUint16(uint16(hdr.SrcAddr))),
		uint32(packet.SwapBytesUint16(uint16(hdr.DstAddr >> 16))),
		uint32(packet.SwapBytesUint16(uint16(hdr.DstAddr))),
		uint32(hdr.NextProtoID),
		uint32(dataLength - packet.UDPLen),
		sum)

	return fixChecksum(sum)
}

func calculateTCPChecksum(tcp *packet.TCPHdr) uint32 {
	return uint32(packet.SwapBytesUint16(tcp.SrcPort)) +
		uint32(packet.SwapBytesUint16(tcp.DstPort)) +
		uint32(packet.SwapBytesUint16(uint16(tcp.SentSeq >> 16))) +
		uint32(packet.SwapBytesUint16(uint16(tcp.SentSeq))) +
		uint32(packet.SwapBytesUint16(uint16(tcp.RecvAck >> 16))) +
		uint32(packet.SwapBytesUint16(uint16(tcp.RecvAck))) +
		uint32(tcp.DataOff << 8) +
		uint32(tcp.TCPFlags) +
		uint32(packet.SwapBytesUint16(tcp.RxWin)) +
		uint32(packet.SwapBytesUint16(tcp.TCPUrp))
}

func CalculateIPv4TCPChecksum(p *packet.Packet) uint16 {
	hdr := p.IPv4
	tcp := p.TCP
	dataLength := packet.SwapBytesUint16(hdr.TotalLength) - packet.IPv4MinLen

	sum := calculateDataChecksum(p.Data, int(dataLength - packet.TCPMinLen), 0)

	sum += calculateIPv4AddrChecksum(hdr) +
		uint32(hdr.NextProtoID) +
		uint32(dataLength) +
		calculateTCPChecksum(tcp)

	return fixChecksum(sum)
}

func calculateIPv6AddrChecksum(hdr *packet.IPv6Hdr) uint32 {
	return uint32(uint16(hdr.SrcAddr[0] << 8) | uint16(hdr.SrcAddr[1])) +
		uint32(uint16(hdr.SrcAddr[2] << 8) | uint16(hdr.SrcAddr[3])) +
		uint32(uint16(hdr.SrcAddr[4] << 8) | uint16(hdr.SrcAddr[5])) +
		uint32(uint16(hdr.SrcAddr[6] << 8) | uint16(hdr.SrcAddr[7])) +
		uint32(uint16(hdr.SrcAddr[8] << 8) | uint16(hdr.SrcAddr[9])) +
		uint32(uint16(hdr.SrcAddr[10] << 8) | uint16(hdr.SrcAddr[11])) +
		uint32(uint16(hdr.SrcAddr[12] << 8) | uint16(hdr.SrcAddr[13])) +
		uint32(uint16(hdr.SrcAddr[14] << 8) | uint16(hdr.SrcAddr[15])) +
		uint32(uint16(hdr.DstAddr[0] << 8) | uint16(hdr.DstAddr[1])) +
		uint32(uint16(hdr.DstAddr[2] << 8) | uint16(hdr.DstAddr[3])) +
		uint32(uint16(hdr.DstAddr[4] << 8) | uint16(hdr.DstAddr[5])) +
		uint32(uint16(hdr.DstAddr[6] << 8) | uint16(hdr.DstAddr[7])) +
		uint32(uint16(hdr.DstAddr[8] << 8) | uint16(hdr.DstAddr[9])) +
		uint32(uint16(hdr.DstAddr[10] << 8) | uint16(hdr.DstAddr[11])) +
		uint32(uint16(hdr.DstAddr[12] << 8) | uint16(hdr.DstAddr[13])) +
		uint32(uint16(hdr.DstAddr[14] << 8) | uint16(hdr.DstAddr[15]))
}

func CalculateIPv6UDPChecksum(p *packet.Packet) uint16 {
	hdr := p.IPv6
	udp := p.UDP
	dataLength := packet.SwapBytesUint16(hdr.PayloadLen) - packet.IPv4MinLen

	sum := calculateDataChecksum(p.Data, int(dataLength - packet.UDPLen), 0)

	sum += calculateIPv6AddrChecksum(hdr) +
		uint32(hdr.PayloadLen) +
		uint32(hdr.Proto) +
		uint32(packet.SwapBytesUint16(udp.SrcPort)) +
		uint32(packet.SwapBytesUint16(udp.DstPort)) +
		uint32(dataLength - packet.UDPLen)

	return fixChecksum(sum)
}

func CalculateIPv6TCPChecksum(p *packet.Packet) uint16 {
	hdr := p.IPv6
	tcp := p.TCP
	dataLength := packet.SwapBytesUint16(hdr.PayloadLen) - packet.IPv4MinLen

	sum := calculateDataChecksum(p.Data, int(dataLength - packet.TCPMinLen), 0)

	sum += calculateIPv6AddrChecksum(hdr) +
		uint32(dataLength) +
		uint32(hdr.Proto) +
		calculateTCPChecksum(tcp)

	return fixChecksum(sum)
}

func CalculateChecksum(p *packet.Packet) {
	if p.Ether.EtherType == packet.SwapBytesUint16(packet.IPV4Number) {
		p.IPv4.HdrChecksum = CalculateIPv4Checksum(p)

		if p.IPv4.NextProtoID == packet.UDPNumber {
			p.UDP.DgramCksum = CalculateIPv4UDPChecksum(p)
		} else if p.IPv4.NextProtoID == packet.TCPNumber {
			p.TCP.Cksum = CalculateIPv4TCPChecksum(p)
		} else {
			println("Unknown IPv4 protocol number", p.IPv4.NextProtoID)
			println("TEST FAILED")
		}
	} else if p.Ether.EtherType == packet.SwapBytesUint16(packet.IPV6Number) {
		if p.IPv6.Proto == packet.UDPNumber {
			p.UDP.DgramCksum = CalculateIPv6UDPChecksum(p)
		} else if p.IPv6.Proto == packet.TCPNumber {
			p.TCP.Cksum = CalculateIPv6TCPChecksum(p)
		} else {
			println("Unknown IPv6 protocol number", p.IPv6.Proto)
			println("TEST FAILED")
		}
	} else {
		println("Unknown packet EtherType", p.Ether.EtherType)
		println("TEST FAILED")
	}
}
