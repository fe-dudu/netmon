package packet

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/fe-dudu/netmon/internal/types"
)

func ParsePacket(packet gopacket.Packet) types.PacketInfo {
	ts := time.Now()
	if meta := packet.Metadata(); meta != nil && !meta.Timestamp.IsZero() {
		ts = meta.Timestamp
	}

	src, dst := Endpoints(packet)
	proto, detail := Classify(packet)

	return types.PacketInfo{
		Timestamp: ts,
		Proto:     proto,
		Src:       src,
		Dst:       dst,
		Detail:    detail,
	}
}

func Endpoints(packet gopacket.Packet) (string, string) {
	src := "unknown"
	dst := "unknown"

	if ipv4 := packet.Layer(layers.LayerTypeIPv4); ipv4 != nil {
		ip := ipv4.(*layers.IPv4)
		src = ip.SrcIP.String()
		dst = ip.DstIP.String()
	} else if ipv6 := packet.Layer(layers.LayerTypeIPv6); ipv6 != nil {
		ip := ipv6.(*layers.IPv6)
		src = ip.SrcIP.String()
		dst = ip.DstIP.String()
	} else if nl := packet.NetworkLayer(); nl != nil {
		src = nl.NetworkFlow().Src().String()
		dst = nl.NetworkFlow().Dst().String()
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		src = fmt.Sprintf("%s:%d", src, tcp.SrcPort)
		dst = fmt.Sprintf("%s:%d", dst, tcp.DstPort)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		src = fmt.Sprintf("%s:%d", src, udp.SrcPort)
		dst = fmt.Sprintf("%s:%d", dst, udp.DstPort)
	}

	return src, dst
}

func Classify(packet gopacket.Packet) (string, string) {
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns := dnsLayer.(*layers.DNS)
		detail := ""
		if len(dns.Questions) > 0 {
			q := dns.Questions[0]
			name := string(q.Name)
			if len(name) > 60 {
				name = name[:57] + "..."
			}
			detail = fmt.Sprintf("Q %s %s", q.Type.String(), name)
		} else if len(dns.Answers) > 0 {
			a := dns.Answers[0]
			name := string(a.Name)
			if len(name) > 60 {
				name = name[:57] + "..."
			}
			detail = fmt.Sprintf("A %s %s", a.Type.String(), name)
		}
		return "DNS", detail
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		if info := MaybeHTTPInfo(tcp); info != "" {
			return "HTTP", info
		}
		if tcp.SrcPort == 443 || tcp.DstPort == 443 {
			return "TLS", ""
		}
		flags := SummarizeTCPFlags(tcp)
		if flags == "" {
			return "TCP", ""
		}
		return "TCP", fmt.Sprintf("flags=%s", flags)
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		if udp.SrcPort == 443 || udp.DstPort == 443 {
			return "QUIC", fmt.Sprintf("len=%d", len(udp.Payload))
		}
		return "UDP", fmt.Sprintf("len=%d", len(udp.Payload))
	}

	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		return "ICMP", ""
	}

	if icmpLayer := packet.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
		return "ICMPv6", ""
	}

	if l := packet.NetworkLayer(); l != nil {
		return l.LayerType().String(), ""
	}

	return "PKT", ""
}

func SummarizeTCPFlags(tcp *layers.TCP) string {
	flags := make([]string, 0, 6)
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}
	return strings.Join(flags, ",")
}

func MaybeHTTPInfo(tcp *layers.TCP) string {
	if len(tcp.Payload) == 0 {
		return ""
	}
	if !(tcp.DstPort == 80 || tcp.SrcPort == 80 || tcp.DstPort == 8080 || tcp.SrcPort == 8080) {
		return ""
	}

	line := FirstLine(tcp.Payload)
	if line == "" {
		return ""
	}

	httpMethods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE"}
	for _, m := range httpMethods {
		if strings.HasPrefix(line, m+" ") {
			return sanitizeHTTPLine(line)
		}
	}
	if strings.HasPrefix(line, "HTTP/") {
		return sanitizeHTTPLine(line)
	}
	return ""
}

func sanitizeHTTPLine(line string) string {
	if idx := strings.Index(line, "?"); idx != -1 {
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			path := parts[1]
			if qIdx := strings.Index(path, "?"); qIdx != -1 {
				parts[1] = path[:qIdx] + " ?..."
			}
			line = strings.Join(parts, " ")
		} else {
			line = line[:idx] + " ?..."
		}
	}
	
	if len(line) > 100 {
		line = line[:97] + "..."
	}
	
	return line
}

func FirstLine(payload []byte) string {
	line := payload
	if idx := bytes.IndexByte(payload, '\n'); idx != -1 {
		line = payload[:idx]
	}
	return strings.TrimSpace(string(line))
}

func MatchesFilter(filterIdx int, pkt types.PacketInfo) bool {
	if filterIdx < 0 || filterIdx >= len(types.ProtocolFilters) {
		return true
	}

	filter := types.ProtocolFilters[filterIdx]

	switch filter.Label {
	case "ALL":
		return true
	case "TCP":
		return pkt.Proto == "TCP" || pkt.Proto == "HTTP" || pkt.Proto == "TLS"
	case "UDP":
		return pkt.Proto == "UDP" || pkt.Proto == "DNS"
	case "QUIC":
		return pkt.Proto == "QUIC"
	case "DNS":
		return pkt.Proto == "DNS"
	case "HTTP":
		return pkt.Proto == "HTTP"
	case "HTTPS":
		return pkt.Proto == "TLS"
	case "ICMP":
		return pkt.Proto == "ICMP" || pkt.Proto == "ICMPv6"
	default:
		return true
	}
}
