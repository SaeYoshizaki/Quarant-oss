package corroborate

import (
	"strings"
	"testing"
	"time"

	"quarant/analyzer"
)

var t0 = time.Date(2018, 4, 10, 12, 0, 0, 0, time.UTC)

func ev(src, typ, flow, conf string, at time.Duration) analyzer.Event {
	return analyzer.Event{Timestamp: t0.Add(at), Type: typ, FlowKey: flow, Confidence: conf, Source: src, Limitation: "Not decrypted."}
}

const flowA = "tcp|192.168.1.10:50000<->203.0.113.5:443"

func TestMerge(t *testing.T) {
	q := []analyzer.Event{
		ev("", "I7_TLS_WEAK_CIPHER_SELECTED", flowA, "medium", 0),
		ev("", "I7_TLS_WEAK_CIPHER_SUITE_OBSERVED", flowA, "medium", 0),
		ev("", "INSECURE_HTTP_BODY_SECRET", "tcp|192.168.1.10:50001<->203.0.113.5:80", "high", 0),
	}
	z := []analyzer.Event{
		ev("zeek", "I7_TLS_WEAK_CIPHER_SELECTED", flowA, "high", 2*time.Second),
		// Same type, other connection, confident: evidence on its own.
		ev("zeek", "I7_TLS_WEAK_VERSION_OBSERVED", "tcp|192.168.1.11:40000<->203.0.113.5:443", "high", time.Second),
		// Name-only match nobody else saw: held back.
		ev("zeek", "INSECURE_HTTP_TOKEN", "tcp|192.168.1.10:50002<->203.0.113.5:80", "low", time.Second),
	}
	res := Merge(q, z)
	if len(res.Events) != 4 || len(res.Held) != 1 {
		t.Fatalf("events=%d held=%d", len(res.Events), len(res.Held))
	}
	sel := res.Events[0]
	if sel.Type != "I7_TLS_WEAK_CIPHER_SELECTED" || strings.Join(sel.Sources, ",") != "quarant,zeek" || sel.Confidence != "high" {
		t.Fatalf("corroborated: %+v", sel)
	}
	if !strings.HasPrefix(sel.Limitation, "Not decrypted. Another parser (zeek)") {
		t.Errorf("limitation = %q", sel.Limitation)
	}
	// Only the same type corroborates.
	if s := res.Events[1]; s.Type != "I7_TLS_WEAK_CIPHER_SUITE_OBSERVED" || strings.Join(s.Sources, ",") != "quarant" || s.Confidence != "medium" {
		t.Fatalf("other type on the same flow: %+v", s)
	}
	if res.Events[3].Type != "I7_TLS_WEAK_VERSION_OBSERVED" || strings.Join(res.Events[3].Sources, ",") != "zeek" {
		t.Fatalf("zeek only: %+v", res.Events[3])
	}
	if res.Held[0].Type != "INSECURE_HTTP_TOKEN" {
		t.Fatalf("held: %+v", res.Held[0])
	}
	if c := res.Counts["I7_TLS_WEAK_CIPHER_SELECTED"]; c.Both != 1 || c.OtherAbsorbed != 1 || c.QuarantOnly != 0 {
		t.Errorf("counts: %+v", c)
	}
	if c := res.Counts["INSECURE_HTTP_TOKEN"]; c.OtherHeld != 1 {
		t.Errorf("held count: %+v", c)
	}
	// The inputs are left alone.
	if q[0].Sources != nil || q[0].Confidence != "medium" {
		t.Errorf("input modified: %+v", q[0])
	}
}

func TestMergeWindow(t *testing.T) {
	// The flow key came back after Quarant had dropped the flow (source
	// port reused): two different connections.
	q := []analyzer.Event{ev("", "I7_TLS_WEAK_VERSION_OBSERVED", flowA, "high", 0)}
	z := []analyzer.Event{ev("zeek", "I7_TLS_WEAK_VERSION_OBSERVED", flowA, "high", 2*time.Hour)}
	res := Merge(q, z)
	if len(res.Events) != 2 || len(res.Events[0].Sources) != 1 || len(res.Events[1].Sources) != 1 {
		t.Fatalf("events: %+v", res.Events)
	}
	// Zeek reports every request on a keep-alive connection (here every
	// 30 minutes); Quarant reports the flow once.
	q = []analyzer.Event{ev("", "INSECURE_HTTP_COOKIE", flowA, "high", 0)}
	z = []analyzer.Event{ev("zeek", "INSECURE_HTTP_COOKIE", flowA, "medium", 0), ev("zeek", "INSECURE_HTTP_COOKIE", flowA, "medium", 30*time.Minute), ev("zeek", "INSECURE_HTTP_COOKIE", flowA, "medium", 60*time.Minute)}
	res = Merge(q, z)
	if len(res.Events) != 1 || res.Counts["INSECURE_HTTP_COOKIE"].OtherAbsorbed != 3 {
		t.Fatalf("keep-alive: %+v %+v", res.Events, res.Counts["INSECURE_HTTP_COOKIE"])
	}
	// No flow key (UDP): never matched.
	q = []analyzer.Event{ev("", "INSECURE_UDP_CREDENTIALS", "", "medium", 0)}
	res = Merge(q, nil)
	if res.Events[0].Confidence != "medium" || res.Counts["INSECURE_UDP_CREDENTIALS"].QuarantOnly != 1 {
		t.Fatalf("no flow key: %+v", res.Events[0])
	}
}
