package network

import (
	"fmt"
	"strings"

	"github.com/fe-dudu/netmon/internal/packet"
	"github.com/fe-dudu/netmon/internal/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	skipPrefixes   = []string{"lo", "lo0", "awdl", "utun", "llw", "vmnet", "br-", "docker", "veth", "virbr", "tap", "tun", "wg", "tailscale", "zt", "ham"}
	preferPrefixes = []string{"en", "eth", "ens", "enp", "enx", "wlan", "wlp", "wifi", "wwan"}
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

func ActiveInterfaces(devs []pcap.Interface) []pcap.Interface {
	var active []pcap.Interface
	for _, dev := range devs {
		name := strings.ToLower(dev.Name)
		if hasPrefix(name, skipPrefixes) {
			continue
		}

		for _, addr := range dev.Addresses {
			if addr.IP != nil && !addr.IP.IsLoopback() {
				active = append(active, dev)
				break
			}
		}
	}

	if len(active) > 0 {
		return active
	}

	for _, dev := range devs {
		name := strings.ToLower(dev.Name)
		if !strings.HasPrefix(name, "lo") && !strings.HasPrefix(name, "lo0") {
			active = append(active, dev)
		}
	}

	if len(active) > 0 {
		return active
	}

	return devs
}

func StartPacketCapture(a *types.App) {
	for idx, handle := range a.Handles {
		if handle == nil {
			continue
		}
		ifaceName := a.Ifaces[idx].Name
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packets := packetSource.Packets()

		go func(name string, in <-chan gopacket.Packet) {
			for {
				select {
				case <-a.StopCh:
					return
				case pkt, ok := <-in:
					if !ok {
						return
					}
					info := packet.ParsePacket(pkt)
					info.Iface = name
					select {
					case a.PacketCh <- info:
					default:
					}
				}
			}
		}(ifaceName, packets)
	}

	go func() {
		for {
			select {
			case <-a.StopCh:
				return
			case info := <-a.PacketCh:
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

func hasPrefix(name string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
