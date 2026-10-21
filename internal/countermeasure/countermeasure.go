// Package countermeasure simulates network countermeasures on a capture:
// it derives gateway rules from the evidence, removes the packets those
// rules would stop, and so lets the same analysis run on the traffic that
// would remain. The device itself is not touched.
//
// The countermeasures are ones a home gateway can apply:
//
//   - block_inbound: connections started from the internet to a device are
//     refused.
//   - block_weak_destinations: a device may not reach the internet
//     endpoints (address and port) where its traffic showed cleartext
//     secrets or media, or weak cryptography.
//   - isolate: a device may talk to the gateway and the internet, not to
//     other hosts in the home network (client isolation, an IoT network).
//
// A TCP connection a gateway refuses never carries application data, so
// dropping all of its packets models what an observer, and an attacker on
// the far side of the gateway, would no longer see. What the device does
// instead (retries, other destinations, a fallback to another protocol) is
// not modelled.
package countermeasure

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"quarant/analyzer"
)

const (
	BlockInbound          = "block_inbound"
	BlockWeakDestinations = "block_weak_destinations"
	Isolate               = "isolate"
)

// Countermeasures lists the simulated countermeasures in a fixed order.
var Countermeasures = []string{BlockInbound, BlockWeakDestinations, Isolate}

// Rule is one gateway rule. Device is the device's address in the
// capture; Peer and PeerPort are set for block_weak_destinations.
type Rule struct {
	Countermeasure string `json:"countermeasure"`
	Device         string `json:"device"`
	Peer           string `json:"peer,omitempty"`
	PeerPort       uint16 `json:"peer_port,omitempty"`
	Reason         string `json:"reason"`
}

// Event types whose internet endpoint block_weak_destinations stops: what
// travels in cleartext or over weak cryptography to that endpoint.
var weakTypes = map[string]bool{
	"INSECURE_HTTP_AUTH": true, "INSECURE_HTTP_COOKIE": true, "INSECURE_HTTP_TOKEN": true,
	"I3_AUTH_TOKEN_IN_URL": true, "INSECURE_HTTP_BODY_SECRET": true, "INSECURE_HTTP_RESPONSE_SECRET": true,
	"INSECURE_MQTT_CREDENTIALS": true, "INSECURE_FTP_CREDENTIALS": true, "INSECURE_TELNET_CREDENTIALS": true,
	"I6_MEDIA_UPLOAD_CLEARTEXT": true, "I6_HTTP_PRIVACY_EXPOSURE": true, "I6_HTTP_UNEXPECTED_PII": true,
	"I7_TLS_WEAK_VERSION_OBSERVED": true, "I7_TLS_WEAK_CIPHER_SELECTED": true, "I7_TLS_WEAK_CERTIFICATE_OBSERVED": true,
	"I7_SSH_WEAK_VERSION_OBSERVED": true, "I7_SSH_WEAK_ALGORITHM_SELECTED": true,
}

// Plan derives the rules from the evidence. Only events at medium or high
// confidence count (low ones are not evidence on their own, D25), and only
// events about a device in the home network.
func Plan(events []analyzer.Event, local analyzer.LocalNetworks) []Rule {
	seen := map[string]bool{}
	var out []Rule
	add := func(r Rule) {
		k := r.Countermeasure + "|" + r.Device + "|" + r.Peer + "|" + fmt.Sprint(r.PeerPort)
		if !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}
	for _, e := range events {
		dev := e.DeviceKey
		if e.Debug || e.Confidence == "low" || dev == "" || !local.Contains(dev) || e.SrcIP == "" || e.DstIP == "" {
			continue
		}
		peer, peerPort := e.DstIP, e.DstPort
		if dev == e.DstIP {
			peer, peerPort = e.SrcIP, e.SrcPort
		}
		switch {
		case !local.Contains(peer) && dev == e.DstIP:
			// The connection came from outside to the device.
			add(Rule{Countermeasure: BlockInbound, Device: dev, Reason: e.Type})
		case !local.Contains(peer) && weakTypes[e.Type]:
			add(Rule{Countermeasure: BlockWeakDestinations, Device: dev, Peer: peer, PeerPort: peerPort, Reason: e.Type})
		case local.Contains(peer):
			add(Rule{Countermeasure: Isolate, Device: dev, Reason: e.Type})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Countermeasure != b.Countermeasure {
			return a.Countermeasure < b.Countermeasure
		}
		if a.Device != b.Device {
			return a.Device < b.Device
		}
		if a.Peer != b.Peer {
			return a.Peer < b.Peer
		}
		return a.PeerPort < b.PeerPort
	})
	return out
}

// Stats counts what Filter kept and dropped.
type Stats struct {
	Packets        int            `json:"packets"`
	Dropped        int            `json:"dropped"`
	DroppedBy      map[string]int `json:"dropped_by"`
	FlowsBlocked   int            `json:"flows_blocked"`
	NonIPPassed    int            `json:"non_ip_passed"`
	UnparsedPassed int            `json:"unparsed_passed"`
}

// Filter copies the capture from r to w without the packets that the
// rules of the chosen countermeasures stop. gateways are the home
// network's gateway addresses, which isolation leaves reachable.
// flowState carries flow directions across calls, so a capture split
// into files can be filtered file by file in order.
type Filter struct {
	rules    []Rule
	chosen   map[string]bool
	local    analyzer.LocalNetworks
	gateways map[string]bool
	// first direction seen per flow: true when the first packet came from
	// outside the home network to a device
	inbound map[string]bool
	blocked map[string]bool
	Stats   Stats
}

func NewFilter(rules []Rule, chosen []string, local analyzer.LocalNetworks, gateways []string) *Filter {
	f := &Filter{rules: rules, chosen: map[string]bool{}, local: local, gateways: map[string]bool{},
		inbound: map[string]bool{}, blocked: map[string]bool{}, Stats: Stats{DroppedBy: map[string]int{}}}
	for _, c := range chosen {
		f.chosen[c] = true
	}
	for _, g := range gateways {
		f.gateways[strings.TrimSpace(g)] = true
	}
	return f
}

// Copy filters one capture file.
func (f *Filter) Copy(r io.Reader, w *pcapgo.Writer, writeHeader bool) error {
	rd, err := pcapgo.NewReader(r)
	if err != nil {
		return err
	}
	if writeHeader {
		if err := w.WriteFileHeader(rd.Snaplen(), rd.LinkType()); err != nil {
			return err
		}
	}
	for {
		data, ci, err := rd.ReadPacketData()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		f.Stats.Packets++
		if by := f.decide(data, rd.LinkType()); by != "" {
			f.Stats.Dropped++
			f.Stats.DroppedBy[by]++
			continue
		}
		if err := w.WritePacket(ci, data); err != nil {
			return err
		}
	}
}

// decide returns the countermeasure that stops the packet, or "".
func (f *Filter) decide(data []byte, lt layers.LinkType) string {
	p := gopacket.NewPacket(data, lt, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	var src, dst string
	if ip := p.Layer(layers.LayerTypeIPv4); ip != nil {
		v := ip.(*layers.IPv4)
		src, dst = v.SrcIP.String(), v.DstIP.String()
	} else if ip := p.Layer(layers.LayerTypeIPv6); ip != nil {
		v := ip.(*layers.IPv6)
		src, dst = v.SrcIP.String(), v.DstIP.String()
	} else {
		f.Stats.NonIPPassed++
		return ""
	}
	var proto string
	var sport, dport uint16
	if t := p.Layer(layers.LayerTypeTCP); t != nil {
		v := t.(*layers.TCP)
		proto, sport, dport = "tcp", uint16(v.SrcPort), uint16(v.DstPort)
	} else if u := p.Layer(layers.LayerTypeUDP); u != nil {
		v := u.(*layers.UDP)
		proto, sport, dport = "udp", uint16(v.SrcPort), uint16(v.DstPort)
	}
	key := flowID(proto, src, sport, dst, dport)
	if f.blocked[key] {
		return "flow"
	}
	if _, ok := f.inbound[key]; !ok {
		f.inbound[key] = !f.local.Contains(src) && f.local.Contains(dst)
	}
	for _, r := range f.rules {
		if !f.chosen[r.Countermeasure] || (src != r.Device && dst != r.Device) {
			continue
		}
		peer, peerPort := dst, dport
		if dst == r.Device {
			peer, peerPort = src, sport
		}
		hit := false
		switch r.Countermeasure {
		case BlockInbound:
			hit = f.inbound[key]
		case BlockWeakDestinations:
			hit = peer == r.Peer && (r.PeerPort == 0 || peerPort == r.PeerPort)
		case Isolate:
			// Unicast to another home host that is not the gateway.
			hit = f.local.Contains(peer) && !f.gateways[peer]
		}
		if hit {
			if proto != "" {
				if !f.blocked[key] {
					f.Stats.FlowsBlocked++
				}
				f.blocked[key] = true
			}
			return r.Countermeasure
		}
	}
	return ""
}

// flowID is the same for both directions of a flow.
func flowID(proto, a string, ap uint16, b string, bp uint16) string {
	x, y := fmt.Sprintf("%s:%d", a, ap), fmt.Sprintf("%s:%d", b, bp)
	if x > y {
		x, y = y, x
	}
	return proto + "|" + x + "|" + y
}
