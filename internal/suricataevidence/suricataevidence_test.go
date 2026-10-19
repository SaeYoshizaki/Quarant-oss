package suricataevidence

import (
	"strings"
	"testing"

	"quarant/analyzer"
)

var local = analyzer.DefaultLocalNetworks()

const eve = `{"timestamp":"2018-06-02T08:00:00.000000+0900","flow_id":1,"event_type":"alert","src_ip":"149.171.36.232","src_port":5000,"dest_ip":"192.168.1.248","dest_port":161,"proto":"UDP","alert":{"signature_id":2101411,"signature":"GPL SNMP public access udp","category":"Attempted Information Leak"}}
{"timestamp":"2018-06-02T08:00:05.000000+0900","flow_id":1,"event_type":"alert","src_ip":"149.171.36.232","src_port":5000,"dest_ip":"192.168.1.248","dest_port":161,"proto":"UDP","alert":{"signature_id":2101411,"signature":"GPL SNMP public access udp","category":"Attempted Information Leak"}}
{"timestamp":"2018-06-02T09:00:00.000000+0900","flow_id":1,"event_type":"flow","src_ip":"149.171.36.232","dest_ip":"192.168.1.248","proto":"UDP","flow":{"pkts_toserver":10,"pkts_toclient":575}}
{"timestamp":"2018-06-02T08:10:00.000000+0900","flow_id":2,"event_type":"alert","src_ip":"129.132.2.21","dest_ip":"192.168.1.165","dest_port":1900,"proto":"UDP","alert":{"signature_id":2019102,"signature":"ET DOS Possible SSDP Amplification Scan in Progress","category":"Attempted Denial of Service"}}
{"timestamp":"2018-06-02T08:20:00.000000+0900","flow_id":3,"event_type":"alert","src_ip":"192.168.100.111","dest_ip":"203.0.113.9","dest_port":6667,"proto":"TCP","alert":{"signature_id":2025391,"signature":"ET MALWARE ELF/Muhstik - IRC CnC Checkin","category":"Malware Command and Control Activity Detected"}}
{"timestamp":"2018-06-02T08:35:00.000000+0900","flow_id":10,"event_type":"alert","src_ip":"77.72.83.20","dest_ip":"192.168.1.175","dest_port":22,"proto":"TCP","alert":{"signature_id":2023753,"signature":"ET SCAN MS Terminal Server Traffic on Non-standard Port","category":"Attempted Information Leak"}}
{"timestamp":"2018-06-02T08:36:00.000000+0900","flow_id":10,"event_type":"flow","src_ip":"77.72.83.20","dest_ip":"192.168.1.175","proto":"TCP","flow":{"pkts_toclient":4},"tcp":{"tcp_flags_tc":"1e"}}
{"timestamp":"2018-06-02T08:37:00.000000+0900","flow_id":11,"event_type":"alert","src_ip":"77.72.83.20","dest_ip":"192.168.1.176","dest_port":3389,"proto":"TCP","alert":{"signature_id":2023753,"signature":"ET SCAN MS Terminal Server Traffic on Non-standard Port","category":"Attempted Information Leak"}}
{"timestamp":"2018-06-02T08:38:00.000000+0900","flow_id":11,"event_type":"flow","src_ip":"77.72.83.20","dest_ip":"192.168.1.176","proto":"TCP","flow":{"pkts_toclient":1},"tcp":{"tcp_flags_tc":"14"}}
{"timestamp":"2018-06-02T08:21:00.000000+0900","flow_id":4,"event_type":"alert","src_ip":"192.168.100.111","dest_ip":"203.0.113.10","dest_port":22,"proto":"TCP","alert":{"signature_id":2003068,"signature":"ET SCAN Potential SSH Scan OUTBOUND","category":"Attempted Information Leak"}}
{"timestamp":"2018-06-02T08:22:00.000000+0900","flow_id":5,"event_type":"alert","src_ip":"192.168.100.111","dest_ip":"203.0.113.11","dest_port":22,"proto":"TCP","alert":{"signature_id":2003068,"signature":"ET SCAN Potential SSH Scan OUTBOUND","category":"Attempted Information Leak"}}
{"timestamp":"2018-06-02T08:30:00.000000+0900","flow_id":6,"event_type":"alert","src_ip":"198.51.100.7","dest_ip":"192.168.1.10","dest_port":443,"proto":"TCP","alert":{"signature_id":2400064,"signature":"ET DROP Spamhaus DROP Listed Traffic Inbound group 65","category":"Misc Attack"}}
{"timestamp":"2018-06-02T08:31:00.000000+0900","flow_id":7,"event_type":"alert","src_ip":"192.168.1.10","dest_ip":"203.0.113.12","dest_port":80,"proto":"TCP","alert":{"signature_id":2013504,"signature":"ET INFO GNU/Linux APT User-Agent Outbound likely related to package management","category":"Not Suspicious Traffic"}}
{"timestamp":"2018-06-02T08:32:00.000000+0900","flow_id":8,"event_type":"alert","src_ip":"192.168.1.10","dest_ip":"203.0.113.12","proto":"TCP","alert":{"signature_id":2200074,"signature":"SURICATA TCPv4 invalid checksum","category":"Generic Protocol Command Decode"}}
{"timestamp":"2018-06-02T08:33:00.000000+0900","flow_id":9,"event_type":"alert","src_ip":"203.0.113.1","dest_ip":"203.0.113.2","dest_port":22,"proto":"TCP","alert":{"signature_id":2003068,"signature":"ET SCAN Potential SSH Scan OUTBOUND","category":"Attempted Information Leak"}}
{"timestamp":"2018-06-02T08:34:00.000000+0900","event_type":"dns","src_ip":"192.168.1.10"}
`

func TestConvert(t *testing.T) {
	c, err := Read(strings.NewReader(eve))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Alerts) != 12 || !c.Answers[1].Answered || c.Answers[11].Answered {
		t.Fatalf("read: alerts=%d answers=%v", len(c.Alerts), c.Answers)
	}
	res := Convert(c, local)
	got := map[string]analyzer.Event{}
	for _, e := range res.Events {
		got[e.DeviceKey+" "+e.Type] = e
		if e.Source != Source || e.Basis != analyzer.BasisReferenceMatch || e.ObservedFact == "" || e.Inference == "" || e.Limitation == "" || e.Confidence == "" {
			t.Errorf("incomplete event: %+v", e)
		}
	}
	if len(res.Events) != 7 {
		t.Fatalf("events: %v", keys(got))
	}
	snmp := got["192.168.1.248 "+TypeInboundAnswered]
	if snmp.Confidence != "medium" || !strings.Contains(snmp.Evidence, "alerts=2 flows=1 answered_flows=1 data_flows=1 peers=1") {
		t.Errorf("answered SNMP: %+v", snmp)
	}
	if e := got["192.168.1.165 "+TypeInboundAttack]; e.Confidence != "low" {
		t.Errorf("unanswered SSDP: %+v", e)
	}
	// TCP: a SYN-ACK is an answer, a bare reset is not.
	if e := got["192.168.1.175 "+TypeInboundAnswered]; !strings.Contains(e.Evidence, "answered_flows=1 data_flows=1") {
		t.Errorf("SYN-ACK and data: %+v", e)
	}
	if _, ok := got["192.168.1.176 "+TypeInboundAttack]; !ok {
		t.Errorf("reset counted as an answer: %v", keys(got))
	}
	if e := got["192.168.100.111 "+TypeMalware]; e.Confidence != "medium" || e.DstPort != 6667 {
		t.Errorf("malware: %+v", e)
	}
	if e := got["192.168.100.111 "+TypeOutboundAttack]; !strings.Contains(e.Evidence, "alerts=2 flows=2 answered_flows=0 data_flows=0 peers=2") {
		t.Errorf("outbound scan: %+v", e)
	}
	if e := got["192.168.1.10 "+TypeReputation]; e.Confidence != "low" {
		t.Errorf("reputation: %+v", e)
	}
	// INFO, the engine's own events and alerts between external hosts.
	if res.Ignored["ET INFO"] != 1 || res.Ignored["SURICATA TCPv4"] != 0 || res.Ignored["SURICATA"] != 1 || res.Ignored["ET SCAN"] != 1 {
		t.Errorf("ignored: %v", res.Ignored)
	}
}

func keys(m map[string]analyzer.Event) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
