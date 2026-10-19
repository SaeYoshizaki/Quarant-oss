package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"quarant/analyzer"
	"quarant/internal/reportapi"
)

type suricataImportConfig struct {
	EVEPath               string
	OutDir                string
	SecurityEventsOutPath string
	AttackEvidenceOutPath string
	TaxonomyPolicyPath    string
}

type suricataImportResult struct {
	SecurityEventCount int
	AttackFindingCount int
	FlowCount          int
	ObservationCount   int
}

type suricataEVERecord struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstIP     string `json:"dest_ip"`
	DstPort   uint16 `json:"dest_port"`
	Proto     string `json:"proto"`
	AppProto  string `json:"app_proto"`
	FlowID    any    `json:"flow_id"`
	Alert     struct {
		Action      string `json:"action"`
		SignatureID any    `json:"signature_id"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert"`
	Flow struct {
		PktsToServer  int   `json:"pkts_toserver"`
		PktsToClient  int   `json:"pkts_toclient"`
		BytesToServer int64 `json:"bytes_toserver"`
		BytesToClient int64 `json:"bytes_toclient"`
	} `json:"flow"`
	DNS struct {
		RRName string `json:"rrname"`
		Query  string `json:"query"`
		Type   string `json:"type"`
	} `json:"dns"`
	HTTP struct {
		Hostname   string `json:"hostname"`
		URL        string `json:"url"`
		HTTPMethod string `json:"http_method"`
	} `json:"http"`
	TLS struct {
		SNI string `json:"sni"`
	} `json:"tls"`
	Raw map[string]any `json:"-"`
}

func runSuricata(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("suricata requires subcommand: import or evidence")
	}
	switch args[0] {
	case "import":
		return runSuricataImportCLI(args[1:], out)
	case "evidence":
		return runSuricataEvidenceCLI(args[1:], out)
	default:
		return fmt.Errorf("unknown suricata subcommand %q; use import or evidence", args[0])
	}
}

func runSuricataImportCLI(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("suricata import", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	cfg := suricataImportConfig{}
	fs.StringVar(&cfg.EVEPath, "eve", "", "Suricata eve.json JSONL path")
	fs.StringVar(&cfg.OutDir, "out-dir", "suricata-run", "directory to write Quarant JSON outputs")
	fs.StringVar(&cfg.SecurityEventsOutPath, "security-events-out", "", "security events JSONL output path (default: out-dir/security_events.jsonl)")
	fs.StringVar(&cfg.AttackEvidenceOutPath, "attack-evidence-out", "", "attack evidence report JSON output path (default: out-dir/attack_evidence_report.json)")
	fs.StringVar(&cfg.TaxonomyPolicyPath, "taxonomy-policy", "", "taxonomy policy JSON path, empty for built-in default")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse suricata import flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("suricata import accepts flags only")
	}
	result, err := runSuricataImport(cfg)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Suricata import complete: security_events=%d attack_findings=%d flows=%d observations=%d out=%s\n",
		result.SecurityEventCount,
		result.AttackFindingCount,
		result.FlowCount,
		result.ObservationCount,
		cfg.OutDir,
	)
	return nil
}

func runSuricataImport(cfg suricataImportConfig) (suricataImportResult, error) {
	if strings.TrimSpace(cfg.EVEPath) == "" {
		return suricataImportResult{}, fmt.Errorf("--eve is required")
	}
	if strings.TrimSpace(cfg.OutDir) == "" {
		return suricataImportResult{}, fmt.Errorf("--out-dir is required")
	}
	if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
		return suricataImportResult{}, err
	}
	records, err := readSuricataEVE(cfg.EVEPath)
	if err != nil {
		return suricataImportResult{}, err
	}
	securityEvents := []reportapi.SecurityEvent{}
	flows := []analyzer.FlowRecord{}
	observations := []analyzer.ObservationRecord{}
	for _, record := range records {
		if strings.EqualFold(record.EventType, "alert") {
			if event, ok := securityEventFromSuricataEVE(record); ok {
				securityEvents = append(securityEvents, event)
			}
		}
		if flow, ok := flowFromSuricataEVE(record); ok {
			flows = append(flows, flow)
		}
		observations = append(observations, observationsFromSuricataEVE(record)...)
	}
	taxonomyPolicy, err := reportapi.LoadSecurityTaxonomyPolicy(cfg.TaxonomyPolicyPath)
	if err != nil {
		return suricataImportResult{}, err
	}
	securityEvents = reportapi.NormalizeSecurityEventsWithPolicy(securityEvents, taxonomyPolicy)
	securityEventsPath := defaultSibling(cfg.SecurityEventsOutPath, cfg.OutDir, "security_events.jsonl")
	attackEvidencePath := defaultSibling(cfg.AttackEvidenceOutPath, cfg.OutDir, "attack_evidence_report.json")
	flowsPath := filepath.Join(cfg.OutDir, "flows.jsonl")
	observationsPath := filepath.Join(cfg.OutDir, "observations.jsonl")
	if err := writeJSONL(securityEventsPath, securityEvents); err != nil {
		return suricataImportResult{}, err
	}
	attackEvidence := reportapi.BuildAttackEvidenceReportWithPolicy(securityEvents, taxonomyPolicy)
	attackEvidence.Source.SecurityEvents = securityEventsPath
	if err := writePrettyJSON(attackEvidencePath, attackEvidence); err != nil {
		return suricataImportResult{}, err
	}
	if err := writeJSONL(flowsPath, flows); err != nil {
		return suricataImportResult{}, err
	}
	if err := writeJSONL(observationsPath, observations); err != nil {
		return suricataImportResult{}, err
	}
	return suricataImportResult{
		SecurityEventCount: len(securityEvents),
		AttackFindingCount: len(attackEvidence.Findings),
		FlowCount:          len(flows),
		ObservationCount:   len(observations),
	}, nil
}

func readSuricataEVE(path string) ([]suricataEVERecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	records := []suricataEVERecord{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}
		// UseNumber keeps 64-bit flow_id values exact; float64 would merge distinct flows.
		var record suricataEVERecord
		dec := json.NewDecoder(strings.NewReader(line))
		dec.UseNumber()
		if err := dec.Decode(&record); err != nil {
			continue
		}
		record.Raw = raw
		records = append(records, record)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return records, nil
}

func securityEventFromSuricataEVE(record suricataEVERecord) (reportapi.SecurityEvent, bool) {
	if strings.TrimSpace(record.SrcIP) == "" || strings.TrimSpace(record.DstIP) == "" {
		return reportapi.SecurityEvent{}, false
	}
	ts := parseSensorTimestamp(record.Timestamp)
	action := strings.TrimSpace(record.Alert.Action)
	priority := record.Alert.Severity
	sid := scalarString(record.Alert.SignatureID)
	signature := strings.TrimSpace(record.Alert.Signature)
	category := strings.TrimSpace(record.Alert.Category)
	protocol := strings.ToLower(strings.TrimSpace(record.Proto))
	direction := securityDirection(record.SrcIP, record.DstIP)
	deviceIP := privateEndpoint(record.SrcIP, record.DstIP)
	verdict := suricataVerdict(action)
	event := reportapi.SecurityEvent{
		Timestamp:       ts,
		Source:          "suricata",
		SourceFormat:    "eve_json",
		Sensor:          "suricata",
		EventType:       "ids_alert",
		AttackCategory:  firstNonEmptyString(category, "ids_alert"),
		AttackTechnique: suricataAttackTechnique(category, signature),
		Severity:        idsSeverity(priority),
		Confidence:      "medium",
		SID:             sid,
		Signature:       signature,
		ClassType:       category,
		Priority:        priority,
		Engine:          "suricata",
		RuleSource:      "suricata_eve",
		FlowID:          scalarString(record.FlowID),
		AlertAction:     action,
		Action:          strings.ToUpper(action),
		Verdict:         verdict,
		Direction:       direction,
		SrcIP:           record.SrcIP,
		SrcPort:         record.SrcPort,
		DstIP:           record.DstIP,
		DstPort:         record.DstPort,
		Protocol:        protocol,
		DeviceIP:        deviceIP,
		AssetRole:       assetRole(deviceIP),
		Evidence: map[string]string{
			"parser":       "suricata_eve_v1",
			"signature":    signature,
			"signature_id": sid,
			"classtype":    category,
			"priority":     strconv.Itoa(priority),
			"flow_id":      scalarString(record.FlowID),
			"alert_action": action,
		},
	}
	event.AggregationKey = strings.Join([]string{event.SrcIP, firstNonEmptyString(event.DeviceIP, event.DstIP), event.Protocol}, "|")
	return event, true
}

func flowFromSuricataEVE(record suricataEVERecord) (analyzer.FlowRecord, bool) {
	if strings.TrimSpace(record.SrcIP) == "" || strings.TrimSpace(record.DstIP) == "" {
		return analyzer.FlowRecord{}, false
	}
	switch strings.ToLower(strings.TrimSpace(record.EventType)) {
	case "flow", "alert", "dns", "http", "tls":
	default:
		return analyzer.FlowRecord{}, false
	}
	app := firstNonEmptyString(record.AppProto, strings.ToLower(strings.TrimSpace(record.EventType)))
	host := strings.TrimSpace(record.HTTP.Hostname)
	sni := strings.TrimSpace(record.TLS.SNI)
	dnsQuery := firstNonEmptyString(record.DNS.RRName, record.DNS.Query)
	observed := firstNonEmptyString(sni, host, dnsQuery, record.DstIP)
	return analyzer.FlowRecord{
		Timestamp:           parseSensorTimestamp(record.Timestamp),
		FlowKey:             firstNonEmptyString(scalarString(record.FlowID), sensorFlowKey(record.Timestamp, record.SrcIP, record.DstIP, record.DstPort, record.Proto)),
		SrcIP:               record.SrcIP,
		SrcPort:             record.SrcPort,
		DstIP:               record.DstIP,
		DstPort:             record.DstPort,
		Protocol:            strings.ToLower(strings.TrimSpace(record.Proto)),
		AppProtocol:         app,
		Host:                host,
		SNI:                 sni,
		HTTPMethod:          record.HTTP.HTTPMethod,
		HTTPPath:            record.HTTP.URL,
		BytesOut:            record.Flow.BytesToServer,
		BytesIn:             record.Flow.BytesToClient,
		PacketCount:         record.Flow.PktsToServer + record.Flow.PktsToClient,
		Direction:           securityDirection(record.SrcIP, record.DstIP),
		ObservedDestination: observed,
	}, true
}

func observationsFromSuricataEVE(record suricataEVERecord) []analyzer.ObservationRecord {
	flow, ok := flowFromSuricataEVE(record)
	if !ok {
		return nil
	}
	base := analyzer.ObservationRecord{
		Timestamp:           flow.Timestamp,
		Kind:                "suricata_" + strings.ToLower(strings.TrimSpace(record.EventType)),
		FlowKey:             flow.FlowKey,
		SrcIP:               flow.SrcIP,
		SrcPort:             flow.SrcPort,
		DstIP:               flow.DstIP,
		DstPort:             flow.DstPort,
		Protocol:            flow.Protocol,
		AppProtocol:         flow.AppProtocol,
		Direction:           flow.Direction,
		ObservedDestination: flow.ObservedDestination,
		Host:                flow.Host,
		SNI:                 flow.SNI,
		HTTPMethod:          flow.HTTPMethod,
		HTTPPath:            flow.HTTPPath,
		BytesOut:            flow.BytesOut,
		BytesIn:             flow.BytesIn,
		PacketCount:         flow.PacketCount,
	}
	if query := firstNonEmptyString(record.DNS.RRName, record.DNS.Query); query != "" {
		base.Kind = "dns_query"
		base.DNSQuery = query
		base.AppProtocol = "dns"
		base.ObservedDestination = query
	}
	return []analyzer.ObservationRecord{base}
}

func suricataVerdict(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "blocked", "drop", "dropped", "reject", "rejected":
		return "blocked"
	case "allowed", "allow", "pass", "accepted":
		return "accepted"
	default:
		return "observed"
	}
}

func suricataAttackTechnique(category, signature string) string {
	value := strings.ToLower(strings.TrimSpace(firstNonEmptyString(category, signature)))
	value = strings.NewReplacer(" ", "_", "-", "_", "/", "_", ".", "_").Replace(value)
	if value == "" {
		return "ids_alert"
	}
	return value
}

func idsSeverity(priority int) string {
	switch {
	case priority <= 0:
		return "WARNING"
	case priority == 1:
		return "HIGH"
	case priority == 2:
		return "WARNING"
	default:
		return "INFO"
	}
}

func writeJSONL[T any](path string, items []T) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	for _, item := range items {
		if err := enc.Encode(item); err != nil {
			return err
		}
	}
	return nil
}

func parseSensorTimestamp(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999-0700", "2006-01-02T15:04:05.999999Z07:00"} {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func sensorFlowKey(parts ...any) string {
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		values = append(values, fmt.Sprint(part))
	}
	sum := sha1.Sum([]byte(strings.Join(values, "|")))
	return "sensor_" + hex.EncodeToString(sum[:])[:12]
}

func scalarString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case int:
		return strconv.Itoa(v)
	case json.Number:
		return v.String()
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func securityDirection(srcIP, dstIP string) string {
	srcPrivate := isPrivateIPString(srcIP)
	dstPrivate := isPrivateIPString(dstIP)
	switch {
	case !srcPrivate && dstPrivate:
		return "inbound"
	case srcPrivate && !dstPrivate:
		return "external"
	case srcPrivate && dstPrivate:
		return "local"
	default:
		return "unknown"
	}
}

func privateEndpoint(srcIP, dstIP string) string {
	if isPrivateIPString(dstIP) {
		return dstIP
	}
	if isPrivateIPString(srcIP) {
		return srcIP
	}
	return ""
}

func assetRole(ip string) string {
	if strings.TrimSpace(ip) == "" || net.ParseIP(strings.TrimSpace(ip)) == nil {
		return ""
	}
	return "iot_device"
}
