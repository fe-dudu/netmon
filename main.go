package main

import (
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

	defaultIdx := network.DefaultInterfaceIndex(devices)
	iface := devices[defaultIdx]

	filterIdx := 0

	handle, err := network.OpenHandle(iface.Name)
	if err != nil {
		log.Fatalf("pcap: failed to open %s: %v", iface.Name, err)
	}
	defer handle.Close()

	filter := types.ProtocolFilters[filterIdx]
	if err := handle.SetBPFFilter(filter.BPF); err != nil {
		log.Fatalf("pcap: failed to set filter %q: %v", filter.BPF, err)
	}

	app := ui.NewApp(iface, handle, filterIdx)

	ui.Run(app)
}

