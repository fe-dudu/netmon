package network

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/fe-dudu/netmon/internal/packet"
	"github.com/fe-dudu/netmon/internal/types"
)

func OpenHandle(iface string) (*pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		return OpenLiveFallback(iface, err)
	}
	defer inactive.CleanUp()

	_ = inactive.SetSnapLen(65535)
	_ = inactive.SetPromisc(true)
	_ = inactive.SetImmediateMode(true)
	_ = inactive.SetTimeout(pcap.BlockForever)

	handle, err := inactive.Activate()
	if err != nil {
		return OpenLiveFallback(iface, fmt.Errorf("activate: %w", err))
	}
	return handle, nil
}

func OpenLiveFallback(iface string, activateErr error) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open live failed after inactive (%v): %w", activateErr, err)
	}
	return handle, nil
}

func DefaultInterfaceIndex(devs []pcap.Interface) int {
	skipPrefixes := []string{
		"lo",
		"awdl",
		"utun",
		"llw",
		"docker",
		"br-",
		"veth",
		"virbr",
		"vmnet",
	}

	for i, dev := range devs {
		name := strings.ToLower(dev.Name)
		
		shouldSkip := false
		for _, prefix := range skipPrefixes {
			if strings.HasPrefix(name, prefix) {
				shouldSkip = true
				break
			}
		}
		if shouldSkip {
			continue
		}

		for _, addr := range dev.Addresses {
			if addr.IP != nil && !addr.IP.IsLoopback() {
				return i
			}
		}
	}

	for i, dev := range devs {
		name := strings.ToLower(dev.Name)
		if !strings.HasPrefix(name, "lo") {
			return i
		}
	}
	
	return 0
}

func StartPacketCapture(a *types.App) {
	packetSource := gopacket.NewPacketSource(a.Handle, a.Handle.LinkType())
	packets := packetSource.Packets()

	go func() {
		for {
			select {
			case <-a.StopCh:
				return
			case pkt, ok := <-packets:
				if !ok {
					return
				}
				select {
				case a.PacketCh <- pkt:
				default:
				}
			}
		}
	}()

	go func() {
		for {
			select {
			case <-a.StopCh:
				return
			case pkt := <-a.PacketCh:
				info := packet.ParsePacket(pkt)
				a.PacketsMutex.Lock()
				a.Packets = append(a.Packets, info)
				if len(a.Packets) > 10000 {
					a.Packets = a.Packets[len(a.Packets)-10000:]
				}
				a.PacketsMutex.Unlock()
			}
		}
	}()
}

