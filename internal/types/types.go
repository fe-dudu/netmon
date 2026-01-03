package types

import (
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/rivo/tview"
)

type FilterChoice struct {
	Label string
	BPF   string
	Desc  string
}

type PacketInfo struct {
	Timestamp time.Time
	Proto     string
	Src       string
	Dst       string
	Detail    string
}

var ProtocolFilters = []FilterChoice{
	{Label: "ALL", BPF: "ip or ip6", Desc: "All IPv4/IPv6 traffic (L3)"},
	{Label: "HTTPS", BPF: "tcp port 443", Desc: "HTTPS (HTTP over TLS over TCP 443) (L7, encrypted)"},
	{Label: "HTTP", BPF: "tcp port 80 or tcp port 8080", Desc: "HTTP over TCP ports 80/8080 (L7)"},
	{Label: "DNS", BPF: "udp port 53 or tcp port 53", Desc: "DNS queries and responses (L7)"},
	{Label: "TCP", BPF: "tcp", Desc: "All TCP packets (L4)"},
	{Label: "UDP", BPF: "udp", Desc: "All UDP packets (L4)"},
	{Label: "QUIC", BPF: "udp port 443", Desc: "QUIC over UDP port 443 (UDP-based transport)"},
	{Label: "ICMP", BPF: "icmp or icmp6", Desc: "ICMP/ICMPv6 packets (L3)"},
}

type App struct {
	App         *tview.Application
	PacketView  *tview.TextView
	FilterView  *tview.TextView
	SearchInput *tview.InputField
	MainFlex    *tview.Flex

	Packets      []PacketInfo
	PacketsMutex sync.RWMutex

	CurrentFilterIdx int
	SearchIP         string
	IsSearchMode     bool

	Iface    pcap.Interface
	Handle   *pcap.Handle
	PacketCh chan gopacket.Packet
	StopCh   chan struct{}
}
