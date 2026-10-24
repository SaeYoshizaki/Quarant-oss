package countermeasure

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"quarant/analyzer"
)

var local = analyzer.DefaultLocalNetworks()

func pkt(t *testing.T, src string, sport uint16, dst string, dport uint16, syn bool) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4()}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), SYN: syn, ACK: !syn}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload("x")); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func capture(t *testing.T, frames ...[]byte) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	w := pcapgo.NewWriter(&b)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	for i, f := range frames {
		ci := gopacket.CaptureInfo{Timestamp: time.Unix(1700000000+int64(i), 0), CaptureLength: len(f), Length: len(f)}
		if err := w.WritePacket(ci, f); err != nil {
			t.Fatal(err)
		}
	}
	return &b
}

func count(t *testing.T, b *bytes.Buffer) int {
	t.Helper()
	r, err := pcapgo.NewReader(b)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		if _, _, err := r.ReadPacketData(); err != nil {
			return n
		}
		n++
	}
}

func TestPlan(t *testing.T) {
	ev := func(typ, conf, dev, src string, sport uint16, dst string, dport uint16) analyzer.Event {
		return analyzer.Event{Type: typ, Confidence: conf, DeviceKey: dev, SrcIP: src, SrcPort: sport, DstIP: dst, DstPort: dport}
	}
	rules := Plan([]analyzer.Event{
		ev("INSECURE_HTTP_AUTH", "high", "192.168.1.10", "192.168.1.10", 50000, "203.0.113.5", 80),
		ev("INSECURE_HTTP_AUTH", "high", "192.168.1.10", "192.168.1.10", 50001, "203.0.113.5", 80), // same endpoint
		ev("INSECURE_HTTP_TOKEN", "low", "192.168.1.10", "192.168.1.10", 50002, "203.0.113.6", 80), // low: not evidence
		ev("I3_UNAUTHENTICATED_STREAM_ACCESS", "high", "192.168.1.20", "198.51.100.9", 40000, "192.168.1.20", 554),
		ev("I7_TLS_WEAK_CERTIFICATE_OBSERVED", "high", "192.168.1.20", "192.168.1.30", 40001, "192.168.1.20", 443),
		ev("PERIODIC_COMMUNICATION_OBSERVED", "medium", "192.168.1.10", "192.168.1.10", 50003, "203.0.113.7", 443), // not a weak type
	}, local, nil)
	want := []Rule{
		{Countermeasure: BlockInbound, Device: "192.168.1.20", Reason: "I3_UNAUTHENTICATED_STREAM_ACCESS"},
		{Countermeasure: BlockWeakDestinations, Device: "192.168.1.10", Peer: "203.0.113.5", PeerPort: 80, Reason: "INSECURE_HTTP_AUTH"},
		{Countermeasure: BlockWeakPorts, Device: "192.168.1.10", PeerPort: 80, Reason: "INSECURE_HTTP_AUTH"},
		{Countermeasure: Isolate, Device: "192.168.1.20", Reason: "I7_TLS_WEAK_CERTIFICATE_OBSERVED"},
	}
	if len(rules) != len(want) {
		t.Fatalf("rules = %+v", rules)
	}
	for i := range want {
		if rules[i] != want[i] {
			t.Errorf("rule %d = %+v, want %+v", i, rules[i], want[i])
		}
	}
}

func TestFilter(t *testing.T) {
	dev, cloud, other, gw, attacker := "192.168.1.10", "203.0.113.5", "192.168.1.30", "192.168.1.1", "198.51.100.9"
	frames := [][]byte{
		pkt(t, dev, 50000, cloud, 80, true),               // weak destination
		pkt(t, cloud, 80, dev, 50000, false),              // its answer
		pkt(t, dev, 50001, cloud, 443, true),              // same host, other port: kept
		pkt(t, attacker, 40000, dev, 554, true),           // inbound from the internet
		pkt(t, dev, 554, attacker, 40000, false),          // the device's answer
		pkt(t, other, 40001, dev, 443, true),              // another home host
		pkt(t, dev, 50002, gw, 53, true),                  // the gateway stays reachable
		pkt(t, dev, 50003, "239.255.255.250", 1900, true), // multicast is not unicast to a host
	}
	rules := []Rule{
		{Countermeasure: BlockInbound, Device: dev},
		{Countermeasure: BlockWeakDestinations, Device: dev, Peer: cloud, PeerPort: 80},
		{Countermeasure: Isolate, Device: dev},
	}
	for _, c := range []struct {
		chosen  []string
		kept    int
		dropped map[string]int
	}{
		{nil, 8, map[string]int{}},
		{[]string{BlockWeakDestinations}, 6, map[string]int{BlockWeakDestinations: 1, "flow": 1}},
		{[]string{BlockInbound}, 6, map[string]int{BlockInbound: 1, "flow": 1}},
		{[]string{Isolate}, 7, map[string]int{Isolate: 1}},
		{[]string{BlockInbound, BlockWeakDestinations, Isolate}, 3, nil},
	} {
		f := NewFilter(rules, c.chosen, local, []string{gw})
		var out bytes.Buffer
		if err := f.Copy(capture(t, frames...), pcapgo.NewWriter(&out), true); err != nil {
			t.Fatal(err)
		}
		if got := count(t, &out); got != c.kept {
			t.Errorf("%v: kept %d, want %d (%+v)", c.chosen, got, c.kept, f.Stats)
		}
		for k, v := range c.dropped {
			if f.Stats.DroppedBy[k] != v {
				t.Errorf("%v: dropped by %s = %d, want %d", c.chosen, k, f.Stats.DroppedBy[k], v)
			}
		}
	}
}

func dnsAnswer(t *testing.T, name, ip string) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 9}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, EthernetType: layers.EthernetTypeIPv4}
	ipl := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.168.1.1").To4(), DstIP: net.ParseIP("192.168.1.10").To4()}
	udp := &layers.UDP{SrcPort: 53, DstPort: 40000}
	if err := udp.SetNetworkLayerForChecksum(ipl); err != nil {
		t.Fatal(err)
	}
	dns := &layers.DNS{ID: 1, QR: true, Questions: []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
		Answers: []layers.DNSResourceRecord{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 60, IP: net.ParseIP(ip).To4()}}}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ipl, udp, dns); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A rule from one day applied to another: the device has a new address and
// the service a new one; the MAC and the DNS name still match.
func TestFilterOtherDay(t *testing.T) {
	plan := Plan([]analyzer.Event{{Type: "I7_TLS_WEAK_VERSION_OBSERVED", Confidence: "high", DeviceKey: "192.168.1.50",
		SrcIP: "192.168.1.50", SrcPort: 50000, DstIP: "203.0.113.5", DstPort: 443, Evidence: "risk_kind=deprecated_tls_version sni=api.Example.com"}},
		local, func(string) string { return "02:00:00:00:00:01" })
	if len(plan) != 2 || plan[0].Domain != "api.example.com" || plan[0].DeviceMAC != "02:00:00:00:00:01" || plan[1].Countermeasure != BlockWeakPorts {
		t.Fatalf("plan = %+v", plan)
	}
	// pkt() sends from MAC 02:00:00:00:00:01; the device is now .10.
	frames := [][]byte{
		dnsAnswer(t, "api.example.com", "198.51.100.77"),
		pkt(t, "192.168.1.10", 50000, "198.51.100.77", 443, true), // same service, new address
		pkt(t, "192.168.1.10", 50001, "198.51.100.78", 443, true), // another service
	}
	f := NewFilter(plan, []string{BlockWeakDestinations}, local, nil)
	var out bytes.Buffer
	if err := f.Copy(capture(t, frames...), pcapgo.NewWriter(&out), true); err != nil {
		t.Fatal(err)
	}
	if got := count(t, &out); got != 2 || f.Stats.DroppedBy[BlockWeakDestinations] != 1 {
		t.Fatalf("kept %d, stats %+v", got, f.Stats)
	}
}

func pktMAC(t *testing.T, srcMAC, dstMAC net.HardwareAddr, src string, sport uint16, dst string, dport uint16, syn bool) []byte {
	t.Helper()
	b := pkt(t, src, sport, dst, dport, syn)
	copy(b[0:6], dstMAC)
	copy(b[6:12], srcMAC)
	return b
}

func TestBaselines(t *testing.T) {
	iot, phone, gwMAC := net.HardwareAddr{2, 0, 0, 0, 0, 1}, net.HardwareAddr{2, 0, 0, 0, 0, 7}, net.HardwareAddr{2, 0, 0, 0, 0, 9}
	dev, ph, gw, cloud, other := "192.168.1.10", "192.168.1.30", "192.168.1.1", "203.0.113.5", "198.51.100.9"
	frames := [][]byte{
		pktMAC(t, iot, gwMAC, dev, 50000, cloud, 80, true),  // 0 cleartext port to the internet
		pktMAC(t, iot, gwMAC, dev, 50001, cloud, 443, true), // 1 TLS to the internet
		pktMAC(t, gwMAC, iot, other, 40000, dev, 22, true),  // 2 inbound from the internet
		pktMAC(t, phone, iot, ph, 40001, dev, 8080, true),   // 3 phone to the device
		pktMAC(t, iot, gwMAC, dev, 50002, gw, 53, true),     // 4 the gateway
		pktMAC(t, iot, gwMAC, dev, 50003, other, 443, true), // 5 another internet destination
		pktMAC(t, phone, gwMAC, ph, 40002, other, 80, true), // 6 the phone's own traffic
	}
	run := func(rules []Rule, chosen []string) (int, Stats) {
		f := NewFilter(rules, chosen, local, []string{gw})
		f.SetNonIoT([]string{phone.String()})
		var out bytes.Buffer
		if err := f.Copy(capture(t, frames...), pcapgo.NewWriter(&out), true); err != nil {
			t.Fatal(err)
		}
		return count(t, &out), f.Stats
	}
	for _, c := range []struct {
		cond string
		kept int
	}{
		{RouterDefault, 6},       // frame 2
		{IsolateIoT, 6},          // frame 3
		{BlockCleartextPorts, 6}, // frame 0; the phone's port 80 is not an IoT device's
	} {
		rules, err := Baseline(c.cond)
		if err != nil {
			t.Fatal(err)
		}
		if kept, st := run(rules, []string{c.cond}); kept != c.kept {
			t.Errorf("%s: kept %d, want %d (%+v)", c.cond, kept, c.kept, st)
		}
	}
	// Allowlist learned from a capture where the device reached only the
	// cloud: the other internet destination and the inbound connection are
	// stopped; home traffic is not touched.
	l := NewLearner(local, []string{gw})
	l.SetNonIoT([]string{phone.String()})
	var sink bytes.Buffer
	if err := l.Copy(capture(t, frames[0], frames[1]), pcapgo.NewWriter(&sink), true); err != nil {
		t.Fatal(err)
	}
	allow := l.AllowlistRules()
	if len(allow) != 1 || allow[0].Peer != cloud || allow[0].DeviceMAC != iot.String() {
		t.Fatalf("allowlist = %+v", allow)
	}
	if kept, st := run(allow, []string{Allowlist}); kept != 5 || st.BlockedDestinations != 1 {
		t.Errorf("allowlist: kept %d (%+v)", kept, st)
	}
	// The broad Quarant rule closes the port towards every internet
	// destination, not just the one seen.
	broad := []Rule{{Countermeasure: BlockWeakPorts, Device: dev, DeviceMAC: iot.String(), PeerPort: 443}}
	if kept, _ := run(broad, []string{BlockWeakPorts}); kept != 5 {
		t.Errorf("broad: kept %d, want 5", kept)
	}
}
