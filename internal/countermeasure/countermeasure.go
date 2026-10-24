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
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"quarant/analyzer"
)

const (
	// Quarant's countermeasures, derived from each device's evidence.
	BlockInbound          = "block_inbound"
	BlockWeakDestinations = "block_weak_destinations"
	Isolate               = "isolate"
	// BlockWeakPorts is the broad form of BlockWeakDestinations: the
	// device may not use the port of its weak traffic towards any
	// internet destination.
	BlockWeakPorts = "block_weak_ports"

	// Baselines that use no knowledge of the devices (RESEARCH.md §9).
	// RouterDefault: a home router's default, refusing connections that
	// start from the internet, for every host.
	RouterDefault = "router_default"
	// IsolateIoT: IoT devices on a network of their own; they cannot
	// reach the home's other hosts (phones, computers), only the gateway,
	// each other and the internet.
	IsolateIoT = "isolate_iot"
	// BlockCleartextPorts: IoT devices may not open connections to the
	// internet on ports of common cleartext protocols.
	BlockCleartextPorts = "block_cleartext_ports"
	// Allowlist: each IoT device may reach only the internet destinations
	// it reached during a learning period (Learn).
	Allowlist = "allowlist"
)

// CleartextPorts are the ports BlockCleartextPorts closes: HTTP, FTP,
// Telnet, MQTT.
var CleartextPorts = map[uint16]bool{80: true, 21: true, 23: true, 1883: true}

// AllDevices in Rule.Device means every IoT device of the capture (every
// home host whose MAC is not listed as non-IoT and that is not the
// gateway).
const AllDevices = "*"

// Baseline returns the rule of a baseline condition.
func Baseline(condition string) ([]Rule, error) {
	switch condition {
	case RouterDefault, IsolateIoT, BlockCleartextPorts:
		return []Rule{{Countermeasure: condition, Device: AllDevices, Reason: "baseline"}}, nil
	}
	return nil, fmt.Errorf("unknown baseline %q (use %s, %s or %s)", condition, RouterDefault, IsolateIoT, BlockCleartextPorts)
}

// Countermeasures lists the simulated countermeasures in a fixed order.
var Countermeasures = []string{BlockInbound, BlockWeakDestinations, Isolate, BlockWeakPorts, RouterDefault, IsolateIoT, BlockCleartextPorts, Allowlist}

// Rule is one gateway rule. Device is the device's address in the
// capture; Peer and PeerPort are set for block_weak_destinations.
//
// A rule applied to another capture than the one it came from should name
// the device by MAC (DeviceMAC) and the destination by name (Domain):
// addresses change between days (DHCP leases, cloud load balancing). A
// gateway that blocks by name learns the addresses from the DNS answers
// it relays; Filter does the same with the DNS answers in the capture.
type Rule struct {
	Countermeasure string `json:"countermeasure"`
	Device         string `json:"device"`
	DeviceMAC      string `json:"device_mac,omitempty"`
	Peer           string `json:"peer,omitempty"`
	PeerPort       uint16 `json:"peer_port,omitempty"`
	Domain         string `json:"domain,omitempty"`
	Reason         string `json:"reason"`
}

// domainRe takes the destination name from an event's evidence (Quarant's
// sni=/host=, the Zeek path's peer=).
var domainRe = regexp.MustCompile(`\b(?:sni|host|peer)="?([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,63})\b`)

func domainOf(evidence string) string {
	m := domainRe.FindStringSubmatch(evidence)
	if m == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(m[1], "."))
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
// PlanOptions narrows what a plan is made from.
type PlanOptions struct {
	// Counts, when set, keeps only events that are evidence of a violation
	// (EvidenceMap.Counts).
	Counts func(analyzer.Event) bool
	// NonIoT lists MACs of home hosts that are not IoT devices; they get no
	// rules (the baselines apply to IoT devices only too).
	NonIoT map[string]bool
}

// macOf gives a device's MAC in this capture ("" when unknown).
func Plan(events []analyzer.Event, local analyzer.LocalNetworks, macOf func(ip string) string, opts ...PlanOptions) []Rule {
	if macOf == nil {
		macOf = func(string) string { return "" }
	}
	var o PlanOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	seen := map[string]bool{}
	var out []Rule
	add := func(r Rule) {
		r.DeviceMAC = strings.ToLower(macOf(r.Device))
		k := r.Countermeasure + "|" + r.Device + "|" + r.Peer + "|" + fmt.Sprint(r.PeerPort) + "|" + r.Domain
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
		if o.Counts != nil && !o.Counts(e) || o.NonIoT[strings.ToLower(macOf(dev))] {
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
			add(Rule{Countermeasure: BlockWeakDestinations, Device: dev, Peer: peer, PeerPort: peerPort, Domain: domainOf(e.Evidence), Reason: e.Type})
			add(Rule{Countermeasure: BlockWeakPorts, Device: dev, PeerPort: peerPort, Reason: e.Type})
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
	// BlockedDestinations: distinct (device, internet address) pairs with
	// at least one stopped packet, a measure of how much is cut off.
	BlockedDestinations int `json:"blocked_destinations"`
	// TopStopped: the (device MAC, destination) pairs with the most stopped
	// packets; the destination is a DNS name when the capture gave one.
	TopStopped []StoppedCount `json:"top_stopped,omitempty"`
}

type StoppedCount struct {
	Device      string `json:"device"`
	Destination string `json:"destination"`
	By          string `json:"by"`
	Packets     int    `json:"packets"`
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
	// names: the DNS names the capture's answers gave each address
	names map[string]map[string]bool
	// nonIoT: MACs of home hosts that are not IoT devices (phones,
	// computers), for the baselines that apply to every IoT device.
	nonIoT map[string]bool
	// allowIP, allowName: the allowlist per device MAC.
	allowIP, allowName map[string]map[string]bool
	blockedDest        map[string]bool
	stoppedCount       map[string]int
	blockedLabel       map[string]string
	// learning: record the internet destinations of each IoT device
	// instead of filtering (Learn).
	learning bool
	learned  map[string]map[string]bool
	Stats    Stats
}

func NewFilter(rules []Rule, chosen []string, local analyzer.LocalNetworks, gateways []string) *Filter {
	// Only the per-device rules are walked for every packet; baselines and
	// the allowlist are looked up directly.
	var perDevice []Rule
	for _, r := range rules {
		switch r.Countermeasure {
		case BlockInbound, BlockWeakDestinations, BlockWeakPorts, Isolate:
			perDevice = append(perDevice, r)
		}
	}
	f := &Filter{rules: perDevice, chosen: map[string]bool{}, local: local, gateways: map[string]bool{},
		inbound: map[string]bool{}, blocked: map[string]bool{}, names: map[string]map[string]bool{},
		nonIoT: map[string]bool{}, allowIP: map[string]map[string]bool{}, allowName: map[string]map[string]bool{},
		blockedDest: map[string]bool{}, learned: map[string]map[string]bool{}, stoppedCount: map[string]int{}, blockedLabel: map[string]string{},
		Stats: Stats{DroppedBy: map[string]int{}}}
	for _, c := range chosen {
		f.chosen[c] = true
	}
	for _, r := range rules {
		if r.Countermeasure != Allowlist || r.DeviceMAC == "" {
			continue
		}
		m := strings.ToLower(r.DeviceMAC)
		if f.allowIP[m] == nil {
			f.allowIP[m], f.allowName[m] = map[string]bool{}, map[string]bool{}
		}
		if r.Peer != "" {
			f.allowIP[m][r.Peer] = true
		}
		if r.Domain != "" {
			f.allowName[m][r.Domain] = true
		}
	}
	for _, g := range gateways {
		f.gateways[strings.TrimSpace(g)] = true
	}
	return f
}

// SetNonIoT lists the MACs of home hosts that are not IoT devices.
func (f *Filter) SetNonIoT(macs []string) {
	for _, m := range macs {
		if m = strings.ToLower(strings.TrimSpace(m)); m != "" {
			f.nonIoT[m] = true
		}
	}
}

// internet: an address outside the home network that is a host on the
// internet, not a multicast or broadcast group (SSDP, mDNS and the like stay
// inside the home network).
func (f *Filter) internet(ip string) bool {
	a := net.ParseIP(ip)
	if a == nil || f.local.Contains(ip) {
		return false
	}
	return !(a.IsMulticast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || a.Equal(net.IPv4bcast) || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsPrivate())
}

// isIoT: a home host that is not the gateway and not listed as non-IoT.
func (f *Filter) isIoT(ip, mac string) bool {
	return f.local.Contains(ip) && !f.gateways[ip] && !f.nonIoT[mac]
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
	var srcMAC, dstMAC string
	if eth := p.Layer(layers.LayerTypeEthernet); eth != nil {
		v := eth.(*layers.Ethernet)
		srcMAC, dstMAC = v.SrcMAC.String(), v.DstMAC.String()
	}
	if d := p.Layer(layers.LayerTypeDNS); d != nil {
		f.learnNames(d.(*layers.DNS))
	}
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
	var syn, ack bool
	if t := p.Layer(layers.LayerTypeTCP); t != nil {
		v := t.(*layers.TCP)
		proto, sport, dport = "tcp", uint16(v.SrcPort), uint16(v.DstPort)
		syn, ack = v.SYN, v.ACK
	} else if u := p.Layer(layers.LayerTypeUDP); u != nil {
		v := u.(*layers.UDP)
		proto, sport, dport = "udp", uint16(v.SrcPort), uint16(v.DstPort)
	}
	key := flowID(proto, src, sport, dst, dport)
	if f.blocked[key] {
		f.stoppedCount[f.blockedLabel[key]]++
		return "flow"
	}
	if _, ok := f.inbound[key]; !ok {
		f.inbound[key] = startsInbound(proto, f.local.Contains(src), f.local.Contains(dst), syn, ack, sport, dport)
	}
	if f.learning {
		f.learn(src, srcMAC, dst, dstMAC, f.inbound[key])
		return ""
	}
	stop := func(by, devMAC, peer string) string {
		if proto != "" {
			if !f.blocked[key] {
				f.Stats.FlowsBlocked++
			}
			f.blocked[key] = true
		}
		if peer != "" && f.internet(peer) && !f.blockedDest[devMAC+"|"+peer] {
			f.blockedDest[devMAC+"|"+peer] = true
			f.Stats.BlockedDestinations++
		}
		lbl := devMAC + "|" + f.label(peer) + "|" + by
		f.stoppedCount[lbl]++
		if proto != "" {
			f.blockedLabel[key] = lbl
		}
		return by
	}
	// Baselines over every device first.
	if f.chosen[RouterDefault] && f.inbound[key] {
		return stop(RouterDefault, dstMAC, src)
	}
	srcIoT, dstIoT := f.isIoT(src, srcMAC), f.isIoT(dst, dstMAC)
	if f.chosen[IsolateIoT] {
		// One end an IoT device, the other a home host that is not IoT.
		if srcIoT && f.local.Contains(dst) && !f.gateways[dst] && f.nonIoT[dstMAC] ||
			dstIoT && f.local.Contains(src) && !f.gateways[src] && f.nonIoT[srcMAC] {
			return stop(IsolateIoT, "", "")
		}
	}
	if f.chosen[BlockCleartextPorts] && proto == "tcp" {
		if srcIoT && f.internet(dst) && CleartextPorts[dport] && !f.inbound[key] {
			return stop(BlockCleartextPorts, srcMAC, dst)
		}
		if dstIoT && f.internet(src) && CleartextPorts[sport] && !f.inbound[key] {
			return stop(BlockCleartextPorts, dstMAC, src)
		}
	}
	if f.chosen[Allowlist] {
		if srcIoT && f.internet(dst) && !f.allowed(srcMAC, dst) {
			return stop(Allowlist, srcMAC, dst)
		}
		if dstIoT && f.internet(src) && !f.allowed(dstMAC, src) {
			return stop(Allowlist, dstMAC, src)
		}
	}
	for _, r := range f.rules {
		if !f.chosen[r.Countermeasure] {
			continue
		}
		// The device by MAC when the rule has one (addresses change
		// between captures), else by address.
		var devIsSrc, devIsDst bool
		if r.DeviceMAC != "" {
			devIsSrc, devIsDst = srcMAC == r.DeviceMAC && f.local.Contains(src), dstMAC == r.DeviceMAC && f.local.Contains(dst)
		} else {
			devIsSrc, devIsDst = src == r.Device, dst == r.Device
		}
		if !devIsSrc && !devIsDst {
			continue
		}
		peer, peerPort := dst, dport
		if devIsDst {
			peer, peerPort = src, sport
		}
		hit := false
		switch r.Countermeasure {
		case BlockInbound:
			hit = f.inbound[key]
		case BlockWeakDestinations:
			portOK := r.PeerPort == 0 || peerPort == r.PeerPort
			hit = portOK && (peer == r.Peer || r.Domain != "" && f.hasName(peer, r.Domain))
		case BlockWeakPorts:
			hit = f.internet(peer) && peerPort == r.PeerPort && !f.inbound[key]
		case Isolate:
			// Unicast to another home host that is not the gateway.
			hit = f.local.Contains(peer) && !f.gateways[peer]
		}
		if hit {
			devMAC := srcMAC
			if devIsDst {
				devMAC = dstMAC
			}
			return stop(r.Countermeasure, devMAC, peer)
		}
	}
	return ""
}

// label names a destination for TopStopped: its DNS name when known.
func (f *Filter) label(ip string) string {
	if ip == "" {
		return ""
	}
	best := ""
	for n := range f.names[ip] {
		if best == "" || n < best {
			best = n
		}
	}
	if best != "" {
		return best
	}
	return ip
}

// Finish fills Stats.TopStopped (the 30 largest).
func (f *Filter) Finish() {
	var all []StoppedCount
	for k, n := range f.stoppedCount {
		parts := strings.SplitN(k, "|", 3)
		all = append(all, StoppedCount{Device: parts[0], Destination: parts[1], By: parts[2], Packets: n})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Packets != all[j].Packets {
			return all[i].Packets > all[j].Packets
		}
		return all[i].Device+all[i].Destination < all[j].Device+all[j].Destination
	})
	if len(all) > 30 {
		all = all[:30]
	}
	f.Stats.TopStopped = all
}

// allowed: the device reached this address, or a name of it, while the
// allowlist was learned.
func (f *Filter) allowed(mac, ip string) bool {
	if f.allowIP[mac][ip] {
		return true
	}
	for n := range f.names[ip] {
		if f.allowName[mac][n] {
			return true
		}
	}
	return false
}

// learn records the destinations of connections the device started (and
// the answers to them); connections from the internet are not learned, so
// the allowlist does not admit them.
func (f *Filter) learn(src, srcMAC, dst, dstMAC string, inbound bool) {
	rec := func(mac, peer string) {
		if f.learned[mac] == nil {
			f.learned[mac] = map[string]bool{}
		}
		f.learned[mac]["ip|"+peer] = true
		for n := range f.names[peer] {
			f.learned[mac]["name|"+n] = true
		}
	}
	if inbound {
		return
	}
	if f.isIoT(src, srcMAC) && f.internet(dst) {
		rec(srcMAC, dst)
	}
	if f.isIoT(dst, dstMAC) && f.internet(src) {
		rec(dstMAC, src)
	}
}

// NewLearner returns a Filter that records each IoT device's internet
// destinations (addresses and the DNS names that led to them) instead of
// filtering; Allowlist turns the record into rules.
func NewLearner(local analyzer.LocalNetworks, gateways []string) *Filter {
	f := NewFilter(nil, nil, local, gateways)
	f.learning = true
	return f
}

// AllowlistRules turns what a learner recorded into Allowlist rules.
func (f *Filter) AllowlistRules() []Rule {
	var out []Rule
	macs := make([]string, 0, len(f.learned))
	for m := range f.learned {
		macs = append(macs, m)
	}
	sort.Strings(macs)
	for _, m := range macs {
		keys := make([]string, 0, len(f.learned[m]))
		for k := range f.learned[m] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			kind, v, _ := strings.Cut(k, "|")
			r := Rule{Countermeasure: Allowlist, Device: AllDevices, DeviceMAC: m, Reason: "learned"}
			if kind == "ip" {
				r.Peer = v
			} else {
				r.Domain = v
			}
			out = append(out, r)
		}
	}
	return out
}

// learnNames keeps, for each address in a DNS answer, the names that led to
// it (the question and any CNAMEs).
func (f *Filter) learnNames(d *layers.DNS) {
	if !d.QR || len(d.Answers) == 0 {
		return
	}
	var names []string
	for _, q := range d.Questions {
		names = append(names, strings.ToLower(strings.TrimSuffix(string(q.Name), ".")))
	}
	for _, a := range d.Answers {
		if a.Type == layers.DNSTypeCNAME {
			names = append(names, strings.ToLower(strings.TrimSuffix(string(a.CNAME), ".")))
		}
	}
	for _, a := range d.Answers {
		if (a.Type == layers.DNSTypeA || a.Type == layers.DNSTypeAAAA) && a.IP != nil {
			ip := a.IP.String()
			if f.names[ip] == nil {
				f.names[ip] = map[string]bool{}
			}
			for _, n := range names {
				f.names[ip][n] = true
			}
		}
	}
}

func (f *Filter) hasName(ip, domain string) bool {
	return f.names[ip][domain]
}

// startsInbound decides, from the first packet of a flow in the capture,
// whether the internet side started it. A capture begins in the middle of
// connections the devices opened earlier (a day file starts at midnight),
// so the first packet seen is not always the first packet sent:
//   - TCP: only a SYN without ACK from outside counts; a flow first seen in
//     mid-stream was established before and a router keeps it.
//   - UDP: a datagram from outside counts unless it comes from a
//     well-known service port to a high local port, which is the answer to
//     a request sent before the capture (DNS, NTP, ...).
func startsInbound(proto string, srcLocal, dstLocal, syn, ack bool, sport, dport uint16) bool {
	if srcLocal || !dstLocal {
		return false
	}
	switch proto {
	case "tcp":
		return syn && !ack
	case "udp":
		return !(sport < 1024 && dport >= 1024)
	}
	return true
}

// flowID is the same for both directions of a flow.
func flowID(proto, a string, ap uint16, b string, bp uint16) string {
	x, y := fmt.Sprintf("%s:%d", a, ap), fmt.Sprintf("%s:%d", b, bp)
	if x > y {
		x, y = y, x
	}
	return proto + "|" + x + "|" + y
}
