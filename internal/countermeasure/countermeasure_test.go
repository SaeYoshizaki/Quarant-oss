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
	}, local)
	want := []Rule{
		{Countermeasure: BlockInbound, Device: "192.168.1.20", Reason: "I3_UNAUTHENTICATED_STREAM_ACCESS"},
		{Countermeasure: BlockWeakDestinations, Device: "192.168.1.10", Peer: "203.0.113.5", PeerPort: 80, Reason: "INSECURE_HTTP_AUTH"},
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
		{Countermeasures, 3, nil},
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
