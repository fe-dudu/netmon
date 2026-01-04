package network

import (
	"fmt"
	"strings"
	"sync"

	"github.com/fe-dudu/netmon/internal/packet"
	"github.com/fe-dudu/netmon/internal/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	skipPrefixes = []string{
		// Loopback
		"lo", "lo0",

		// Virtual/Tunnel interfaces
		"utun", "anpi", "stf", "gif",
		"tun", "tap", "ipsec", "ppp",
		"sit", "ip6tnl", "gre", "erspan", "ip6gre",
		"dummy", "teql",

		// Bridge/Virtual networks
		"bridge", "br-", "virbr",

		// P2P/VPN
		"p2p", "wg", "tailscale", "zt",

		// VM/Container
		"vmnet", "veth", "docker",

		// Others
		"ham",
	}

	preferPrefixes = []string{
		// macOS/BSD
		"en", // en0 = WiFi, en1 = Ethernet

		// Linux Ethernet
		"eth", "ens", "enp", "enx", "em",

		// WiFi
		"wlan", "wlp", "wl", "wlx", "wifi",

		// Mobile/WWAN
		"wwan", "wwp",
	}
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
	var preferred []pcap.Interface
	var active []pcap.Interface
	var fallback []pcap.Interface

	for _, dev := range devs {
		name := strings.ToLower(dev.Name)

		if hasPrefix(name, skipPrefixes) {
			continue
		}

		fallback = append(fallback, dev)

		if !hasNonLoopbackIP(dev) {
			continue
		}

		if hasPrefix(name, preferPrefixes) {
			preferred = append(preferred, dev)
		} else {
			active = append(active, dev)
		}
	}

	if len(preferred) > 0 {
		return preferred
	}

	if len(active) > 0 {
		return active
	}

	if len(fallback) > 0 {
		return fallback
	}

	return devs
}

func hasNonLoopbackIP(dev pcap.Interface) bool {
	for _, addr := range dev.Addresses {
		if addr.IP != nil && !addr.IP.IsLoopback() {
			return true
		}
	}
	return false
}

func StartPacketCapture(a *types.App) {
	if a.Wg == nil {
		a.Wg = &sync.WaitGroup{}
	}
	wg := a.Wg

	for idx, handle := range a.Handles {
		if handle == nil {
			continue
		}
		wg.Add(1)
		ifaceName := a.Ifaces[idx].Name
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packets := packetSource.Packets()

		go func(name string, in <-chan gopacket.Packet) {
			defer wg.Done()
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
					case <-a.StopCh:
						return
					case a.PacketCh <- info:
					default:
					}
				}
			}
		}(ifaceName, packets)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-a.StopCh:
				return
			case info, ok := <-a.PacketCh:
				if !ok {
					return
				}
				a.PacketsMutex.Lock()
				a.Packets = append(a.Packets, info)
				if len(a.Packets) > 50000 {
					newPackets := make([]types.PacketInfo, 50000, 50000)
					copy(newPackets, a.Packets[len(a.Packets)-50000:])
					a.Packets = newPackets
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