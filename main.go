package main

import (
	"flag"
	"log"
	"os"
	"runtime"

	"github.com/google/gopacket/pcap"

	"github.com/fe-dudu/netmon/internal/network"
	"github.com/fe-dudu/netmon/internal/types"
	"github.com/fe-dudu/netmon/internal/ui"
)

func main() {
	log.SetFlags(0)

	includeLoopback := flag.Bool("include-loopback", false, "include loopback interfaces such as lo0")
	includeVPN := flag.Bool("include-vpn", false, "include VPN and tunnel interfaces such as utun/tun/wg")
	flag.Parse()

	if runtime.GOOS != "windows" {
		if os.Geteuid() != 0 {
			log.Fatal("This program requires root privileges for packet capture.\nPlease run with sudo or as root.")
		}
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("pcap: failed to list interfaces: %v", err)
	}
	if len(devices) == 0 {
		log.Fatalf("pcap: no interfaces found (need capture permission?)")
	}

	filterIdx := 0
	activeIfaces := network.ActiveInterfaces(devices, network.InterfaceOptions{
		IncludeLoopback: *includeLoopback,
		IncludeVPN:      *includeVPN,
	})
	if len(activeIfaces) == 0 {
		log.Fatalf("pcap: no active interfaces detected")
	}

	handles := make([]*pcap.Handle, 0, len(activeIfaces))
	for _, iface := range activeIfaces {
		handle, err := network.OpenHandle(iface.Name)
		if err != nil {
			log.Fatalf("pcap: failed to open %s: %v", iface.Name, err)
		}
		handles = append(handles, handle)
	}
	defer func() {
		for _, h := range handles {
			if h != nil {
				h.Close()
			}
		}
	}()

	filter := types.ProtocolFilters[filterIdx]
	for i, handle := range handles {
		if err := handle.SetBPFFilter(filter.BPF); err != nil {
			log.Fatalf("pcap: failed to set filter %q on %s: %v", filter.BPF, activeIfaces[i].Name, err)
		}
	}

	app := ui.NewApp(activeIfaces, handles, filterIdx)

	ui.Run(app)
}
