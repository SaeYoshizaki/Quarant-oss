// Package suricataevidence turns Suricata alerts (eve.json) into
// per-device Quarant events. Suricata matches signatures (ET Open); this
// package decides what an alert says about the local device on either end
// and attaches basis, observed fact, inference and limitation like the
// built-in rules do. Every event carries source=suricata.
//
// Alerts are grouped per device, event type and signature: one event says
// how many alerts, flows and peers there were, and from when to when.
//
//   - Malware signatures (ET MALWARE, TROJAN, CNC): the device may be
//     infected. Medium.
//   - Attack signatures (ET SCAN, DOS, EXPLOIT, ...) with the device as the
//     source: the device may be infected or misused. Medium.
//   - Attack signatures with the device as the target: when the device
//     answered (Suricata's flow record: a SYN-ACK back for TCP, any packet
//     back for UDP; a bare RST is no answer), the attacked service is
//     reachable. Medium. Without an answer the device was only targeted.
//     Low.
//   - Reputation lists (ET DROP, CINS, COMPROMISED, TOR, JA3, hostile
//     TLDs): low. The lists are those of the rule download, not of the
//     capture time (S2).
//   - Everything else (INFO, POLICY, CHAT, P2P, ...) and Suricata's own
//     engine events are not converted; Ignored counts them.
package suricataevidence

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"quarant/analyzer"
)

const Source = "suricata"

const (
	TypeMalware         = "SURICATA_MALWARE_SIGNATURE"
	TypeOutboundAttack  = "SURICATA_OUTBOUND_ATTACK_SIGNATURE"
	TypeInboundAnswered = "SURICATA_INBOUND_ATTACK_ANSWERED"
	TypeInboundAttack   = "SURICATA_INBOUND_ATTACK_SIGNATURE"
	TypeReputation      = "SURICATA_REPUTATION_MATCH"
	// eve.json writes the zone without a colon (+0900).
	eveTimestampLayout = "2006-01-02T15:04:05.999999-0700"
)

// Alert is the part of an eve.json alert record that is used.
type Alert struct {
	Timestamp time.Time
	FlowID    uint64
	SrcIP     string
	DstIP     string
	DstPort   uint16
	Proto     string
	SID       int64
	Signature string
	Category  string
}

// Capture is what Read keeps from eve.json: the alerts, and for every flow
// whether the server (the side that did not open it) answered.
type Capture struct {
	Alerts         []Alert
	Answers        map[uint64]Answer
	SkippedRecords int
}

// Answer is what the server sent back on a flow.
type Answer struct {
	// Answered: a SYN-ACK (TCP) or any packet (other protocols).
	Answered bool
	// Data: payload back (TCP PSH; any packet for other protocols).
	Data bool
}

type eveRecord struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	FlowID    uint64 `json:"flow_id"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dest_ip"`
	DstPort   uint16 `json:"dest_port"`
	Proto     string `json:"proto"`
	Alert     struct {
		SID       int64  `json:"signature_id"`
		Signature string `json:"signature"`
		Category  string `json:"category"`
	} `json:"alert"`
	Flow struct {
		PktsToClient int `json:"pkts_toclient"`
	} `json:"flow"`
	TCP *struct {
		FlagsTC string `json:"tcp_flags_tc"`
	} `json:"tcp"`
}

const (
	tcpSYN = 0x02
	tcpPSH = 0x08
)

func answer(rec eveRecord) Answer {
	if rec.TCP == nil {
		back := rec.Flow.PktsToClient > 0
		return Answer{Answered: back, Data: back}
	}
	flags, err := strconv.ParseUint(rec.TCP.FlagsTC, 16, 8)
	if err != nil {
		return Answer{}
	}
	return Answer{Answered: flags&tcpSYN != 0, Data: flags&tcpPSH != 0}
}

// Read parses eve.json. Only alert and flow records are decoded.
func Read(r io.Reader) (Capture, error) {
	c := Capture{Answers: map[uint64]Answer{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		isAlert := bytes.Contains(line, []byte(`"event_type":"alert"`))
		if !isAlert && !bytes.Contains(line, []byte(`"event_type":"flow"`)) {
			continue
		}
		var rec eveRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			c.SkippedRecords++
			continue
		}
		if !isAlert {
			c.Answers[rec.FlowID] = answer(rec)
			continue
		}
		ts, err := parseTime(rec.Timestamp)
		if err != nil {
			c.SkippedRecords++
			continue
		}
		c.Alerts = append(c.Alerts, Alert{
			Timestamp: ts, FlowID: rec.FlowID, SrcIP: rec.SrcIP, DstIP: rec.DstIP, DstPort: rec.DstPort,
			Proto: strings.ToUpper(rec.Proto), SID: rec.Alert.SID, Signature: rec.Alert.Signature, Category: rec.Alert.Category,
		})
	}
	return c, sc.Err()
}

func parseTime(s string) (time.Time, error) {
	if t, err := time.Parse(eveTimestampLayout, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339Nano, s)
}

type class int

const (
	classIgnore class = iota
	classMalware
	classAttack
	classReputation
)

// Rule families of ET Open and the GPL set, by the word after the prefix.
var (
	malwareFamilies    = map[string]bool{"MALWARE": true, "TROJAN": true, "CNC": true, "WORM": true, "MOBILE_MALWARE": true, "PHISHING": true}
	attackFamilies     = map[string]bool{"SCAN": true, "DOS": true, "EXPLOIT": true, "EXPLOIT_KIT": true, "WEB_SERVER": true, "WEB_SPECIFIC_APPS": true, "ATTACK_RESPONSE": true, "SHELLCODE": true, "SNMP": true, "TELNET": true, "NETBIOS": true, "RPC": true, "FTP": true, "SQL": true, "VOIP": true}
	reputationFamilies = map[string]bool{"DROP": true, "CINS": true, "COMPROMISED": true, "TOR": true, "JA3": true, "DSHIELD": true}
	malwareCategories  = map[string]bool{"Malware Command and Control Activity Detected": true, "A Network Trojan was detected": true}
)

func classify(a Alert) class {
	sig := a.Signature
	if strings.HasPrefix(sig, "SURICATA ") {
		return classIgnore
	}
	fields := strings.Fields(sig)
	if len(fields) < 2 || (fields[0] != "ET" && fields[0] != "GPL") {
		return classIgnore
	}
	family := fields[1]
	switch {
	case malwareFamilies[family] || (malwareCategories[a.Category] && family != "INFO" && family != "HUNTING"):
		return classMalware
	case attackFamilies[family]:
		return classAttack
	case reputationFamilies[family]:
		return classReputation
	case family == "DNS" && strings.Contains(sig, "Likely Hostile"):
		return classReputation
	}
	return classIgnore
}

type groupKey struct {
	device, typ string
	sid         int64
}

type group struct {
	first, last Alert
	alerts      int
	flows       map[uint64]bool
	answered    map[uint64]bool
	data        map[uint64]bool
	peers       map[string]bool
	localPeer   bool
}

// Result is the converted capture.
type Result struct {
	Events []analyzer.Event
	// Ignored counts the alerts not converted, by rule family ("ET INFO").
	Ignored map[string]int
}

// Convert groups the alerts into per-device events. local decides which
// end is a device; an alert between two external addresses is ignored.
func Convert(c Capture, local analyzer.LocalNetworks) Result {
	res := Result{Ignored: map[string]int{}}
	groups := map[groupKey]*group{}
	for _, a := range c.Alerts {
		cl := classify(a)
		srcLocal, dstLocal := local.Contains(a.SrcIP), local.Contains(a.DstIP)
		if cl == classIgnore || (!srcLocal && !dstLocal) {
			res.Ignored[family(a.Signature)]++
			continue
		}
		var device, peer, typ string
		var ans Answer
		switch cl {
		case classMalware, classReputation:
			// The local end, the sender when both are local.
			device, peer = a.SrcIP, a.DstIP
			if !srcLocal {
				device, peer = a.DstIP, a.SrcIP
			}
			typ = TypeMalware
			if cl == classReputation {
				typ = TypeReputation
			}
		case classAttack:
			if srcLocal && !dstLocal {
				device, peer, typ = a.SrcIP, a.DstIP, TypeOutboundAttack
			} else {
				// The target; an attack between two local hosts counts for
				// the target (the source is not known to be compromised from
				// one alert).
				device, peer = a.DstIP, a.SrcIP
				ans = c.Answers[a.FlowID]
				typ = TypeInboundAttack
				if ans.Answered {
					typ = TypeInboundAnswered
				}
			}
		}
		k := groupKey{device, typ, a.SID}
		g := groups[k]
		if g == nil {
			g = &group{first: a, flows: map[uint64]bool{}, answered: map[uint64]bool{}, data: map[uint64]bool{}, peers: map[string]bool{}}
			groups[k] = g
		}
		if a.Timestamp.Before(g.first.Timestamp) {
			g.first = a
		}
		if !a.Timestamp.Before(g.last.Timestamp) {
			g.last = a
		}
		g.alerts++
		g.flows[a.FlowID] = true
		if ans.Answered {
			g.answered[a.FlowID] = true
		}
		if ans.Data {
			g.data[a.FlowID] = true
		}
		g.peers[peer] = true
		g.localPeer = g.localPeer || local.Contains(peer)
	}
	for k, g := range groups {
		res.Events = append(res.Events, event(k, g))
	}
	sort.Slice(res.Events, func(i, j int) bool {
		a, b := res.Events[i], res.Events[j]
		if !a.Timestamp.Equal(b.Timestamp) {
			return a.Timestamp.Before(b.Timestamp)
		}
		if a.DeviceKey != b.DeviceKey {
			return a.DeviceKey < b.DeviceKey
		}
		return a.RuleID < b.RuleID
	})
	return res
}

func family(sig string) string {
	f := strings.Fields(sig)
	switch {
	case len(f) >= 2 && (f[0] == "ET" || f[0] == "GPL"):
		return f[0] + " " + f[1]
	case len(f) >= 1:
		return f[0]
	}
	return ""
}

func event(k groupKey, g *group) analyzer.Event {
	a := g.first
	e := analyzer.Event{
		Timestamp: a.Timestamp,
		Type:      k.typ,
		RuleID:    fmt.Sprintf("SURICATA_SID_%d", k.sid),
		Category:  "ids_alert",
		Source:    Source,
		Basis:     analyzer.BasisReferenceMatch,
		DeviceKey: k.device,
		SrcIP:     a.SrcIP,
		DstIP:     a.DstIP,
		DstPort:   a.DstPort,
	}
	where := "an external host"
	if g.localPeer {
		where = "a host in the monitored network"
	}
	e.Evidence = fmt.Sprintf("sid=%d signature=%q classtype=%q proto=%s dst_port=%d alerts=%d flows=%d answered_flows=%d data_flows=%d peers=%d first=%s last=%s source=suricata",
		k.sid, a.Signature, a.Category, a.Proto, a.DstPort, g.alerts, len(g.flows), len(g.answered), len(g.data), len(g.peers),
		g.first.Timestamp.UTC().Format(time.RFC3339), g.last.Timestamp.UTC().Format(time.RFC3339))
	sigLimit := "A signature match (ET Open) is a pattern on the traffic, not a confirmed infection or attack; rules can match benign traffic."
	switch k.typ {
	case TypeMalware:
		e.Severity = analyzer.SeverityHigh
		e.Confidence = "medium"
		e.Message = "Malware signature matched on this device's traffic (Suricata)."
		e.ObservedFact = fmt.Sprintf("Suricata's rule %q matched %d times on traffic between the device and %d peer(s).", a.Signature, g.alerts, len(g.peers))
		e.Inference = "The device may be infected and talking to a command-and-control server or similar."
		e.Limitation = sigLimit + " Whether the device runs the malware, or only carried traffic that looks like it, is not known."
	case TypeOutboundAttack:
		e.Severity = analyzer.SeverityHigh
		e.Confidence = "medium"
		e.Message = "The device sent traffic matching an attack signature (Suricata)."
		e.ObservedFact = fmt.Sprintf("Suricata's rule %q matched %d times on traffic from the device to %d external host(s).", a.Signature, g.alerts, len(g.peers))
		e.Inference = "The device may be infected or misused to scan or attack other hosts."
		e.Limitation = sigLimit + " The user may have started the traffic on purpose."
	case TypeInboundAnswered:
		e.Severity = analyzer.SeverityWarning
		e.Confidence = "medium"
		e.Message = "The device answered traffic matching an attack signature (Suricata)."
		e.ObservedFact = fmt.Sprintf("Suricata's rule %q matched traffic from %s to the device (%s port %d). The device answered on %d of %d flow(s) and sent data back on %d.", a.Signature, where, a.Proto, a.DstPort, len(g.answered), len(g.flows), len(g.data))
		e.Inference = "The targeted service is reachable from there and accepts this kind of traffic."
		e.Limitation = sigLimit + " An answer does not show the attack succeeded; the data sent back may be an error, a refusal or a banner."
	case TypeInboundAttack:
		e.Severity = analyzer.SeverityInfo
		e.Confidence = "low"
		e.Message = "Traffic matching an attack signature was sent to the device (Suricata)."
		e.ObservedFact = fmt.Sprintf("Suricata's rule %q matched traffic from %s to the device (%s port %d); no answer was recorded (a TCP reset does not count).", a.Signature, where, a.Proto, a.DstPort)
		e.Inference = "The device was targeted. Nothing here says it is affected."
		e.Limitation = sigLimit + " Being targeted is not a property of the device."
	case TypeReputation:
		e.Severity = analyzer.SeverityInfo
		e.Confidence = "low"
		e.Message = "Traffic to or from an address or fingerprint on a reputation list (Suricata)."
		e.ObservedFact = fmt.Sprintf("Suricata's rule %q matched %d times on the device's traffic.", a.Signature, g.alerts)
		e.Inference = "The peer or the client fingerprint is on a list of hosts or software considered bad."
		e.Limitation = "The list is the one of the rule download, not of the capture time; addresses change hands. A listed peer does not show the device is affected."
	}
	return e
}
