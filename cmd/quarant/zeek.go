package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"quarant/analyzer"
)

type zeekImportConfig struct {
	ConnPath string
	DNSPath  string
	HTTPPath string
	TLSPath  string
	SSLPath  string
	OutDir   string
}

type zeekImportResult struct {
	FlowCount        int
	ObservationCount int
}

func runZeek(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("zeek requires subcommand: import, evidence or merge")
	}
	switch args[0] {
	case "import":
		return runZeekImportCLI(args[1:], out)
	case "evidence":
		return runZeekEvidenceCLI(args[1:], out)
	case "merge":
		return runZeekMergeCLI(args[1:], out)
	default:
		return fmt.Errorf("unknown zeek subcommand %q; use import, evidence or merge", args[0])
	}
}

func runZeekImportCLI(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("zeek import", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	cfg := zeekImportConfig{}
	fs.StringVar(&cfg.ConnPath, "conn", "", "Zeek conn.log path")
	fs.StringVar(&cfg.DNSPath, "dns", "", "Zeek dns.log path")
	fs.StringVar(&cfg.HTTPPath, "http", "", "Zeek http.log path")
	fs.StringVar(&cfg.TLSPath, "tls", "", "Zeek tls.log path")
	fs.StringVar(&cfg.SSLPath, "ssl", "", "Zeek ssl.log path; used when --tls is empty")
	fs.StringVar(&cfg.OutDir, "out-dir", "zeek-run", "directory to write Quarant JSON outputs")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse zeek import flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("zeek import accepts flags only")
	}
	result, err := runZeekImport(cfg)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Zeek import complete: flows=%d observations=%d out=%s\n", result.FlowCount, result.ObservationCount, cfg.OutDir)
	return nil
}

func runZeekImport(cfg zeekImportConfig) (zeekImportResult, error) {
	if strings.TrimSpace(cfg.OutDir) == "" {
		return zeekImportResult{}, fmt.Errorf("--out-dir is required")
	}
	if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
		return zeekImportResult{}, err
	}
	flows := []analyzer.FlowRecord{}
	observations := []analyzer.ObservationRecord{}
	connFlows, connObs, err := readZeekConn(cfg.ConnPath)
	if err != nil {
		return zeekImportResult{}, err
	}
	flows = append(flows, connFlows...)
	observations = append(observations, connObs...)
	dnsObs, err := readZeekDNS(cfg.DNSPath)
	if err != nil {
		return zeekImportResult{}, err
	}
	observations = append(observations, dnsObs...)
	httpFlows, httpObs, err := readZeekHTTP(cfg.HTTPPath)
	if err != nil {
		return zeekImportResult{}, err
	}
	flows = append(flows, httpFlows...)
	observations = append(observations, httpObs...)
	tlsPath := firstNonEmptyString(cfg.TLSPath, cfg.SSLPath)
	tlsFlows, tlsObs, err := readZeekTLS(tlsPath)
	if err != nil {
		return zeekImportResult{}, err
	}
	flows = append(flows, tlsFlows...)
	observations = append(observations, tlsObs...)
	if err := writeJSONL(filepath.Join(cfg.OutDir, "flows.jsonl"), flows); err != nil {
		return zeekImportResult{}, err
	}
	if err := writeJSONL(filepath.Join(cfg.OutDir, "observations.jsonl"), observations); err != nil {
		return zeekImportResult{}, err
	}
	return zeekImportResult{FlowCount: len(flows), ObservationCount: len(observations)}, nil
}

func readZeekConn(path string) ([]analyzer.FlowRecord, []analyzer.ObservationRecord, error) {
	rows, err := readZeekRows(path)
	if err != nil {
		return nil, nil, err
	}
	flows := []analyzer.FlowRecord{}
	observations := []analyzer.ObservationRecord{}
	for _, row := range rows {
		flow := analyzer.FlowRecord{
			Timestamp:           zeekTime(row["ts"]),
			FlowKey:             firstNonEmptyString(row["uid"], sensorFlowKey(row["ts"], row["id.orig_h"], row["id.resp_h"], row["id.resp_p"])),
			SrcIP:               row["id.orig_h"],
			SrcPort:             uint16FromString(row["id.orig_p"]),
			DstIP:               row["id.resp_h"],
			DstPort:             uint16FromString(row["id.resp_p"]),
			Protocol:            strings.ToLower(row["proto"]),
			AppProtocol:         strings.ToLower(row["service"]),
			BytesOut:            int64FromString(row["orig_bytes"]),
			BytesIn:             int64FromString(row["resp_bytes"]),
			PacketCount:         intFromString(row["orig_pkts"]) + intFromString(row["resp_pkts"]),
			Direction:           securityDirection(row["id.orig_h"], row["id.resp_h"]),
			ObservedDestination: row["id.resp_h"],
		}
		flows = append(flows, flow)
		observations = append(observations, observationFromFlow(flow, "zeek_conn"))
	}
	return flows, observations, nil
}

func readZeekDNS(path string) ([]analyzer.ObservationRecord, error) {
	rows, err := readZeekRows(path)
	if err != nil {
		return nil, err
	}
	out := []analyzer.ObservationRecord{}
	for _, row := range rows {
		query := row["query"]
		out = append(out, analyzer.ObservationRecord{
			Timestamp:           zeekTime(row["ts"]),
			Kind:                "dns_query",
			FlowKey:             row["uid"],
			SrcIP:               row["id.orig_h"],
			SrcPort:             uint16FromString(row["id.orig_p"]),
			DstIP:               row["id.resp_h"],
			DstPort:             uint16FromString(firstNonEmptyString(row["id.resp_p"], "53")),
			Protocol:            "udp",
			AppProtocol:         "dns",
			Direction:           securityDirection(row["id.orig_h"], row["id.resp_h"]),
			ObservedDestination: query,
			DNSQuery:            query,
			PacketCount:         1,
		})
	}
	return out, nil
}

func readZeekHTTP(path string) ([]analyzer.FlowRecord, []analyzer.ObservationRecord, error) {
	rows, err := readZeekRows(path)
	if err != nil {
		return nil, nil, err
	}
	flows := []analyzer.FlowRecord{}
	observations := []analyzer.ObservationRecord{}
	for _, row := range rows {
		flow := analyzer.FlowRecord{
			Timestamp:           zeekTime(row["ts"]),
			FlowKey:             firstNonEmptyString(row["uid"], sensorFlowKey(row["ts"], row["id.orig_h"], row["host"], row["uri"])),
			SrcIP:               row["id.orig_h"],
			SrcPort:             uint16FromString(row["id.orig_p"]),
			DstIP:               row["id.resp_h"],
			DstPort:             uint16FromString(firstNonEmptyString(row["id.resp_p"], "80")),
			Protocol:            "tcp",
			AppProtocol:         "http",
			Host:                row["host"],
			HTTPMethod:          row["method"],
			HTTPPath:            row["uri"],
			Direction:           securityDirection(row["id.orig_h"], row["id.resp_h"]),
			ObservedDestination: firstNonEmptyString(row["host"], row["id.resp_h"]),
		}
		flows = append(flows, flow)
		observations = append(observations, observationFromFlow(flow, "http_request"))
	}
	return flows, observations, nil
}

func readZeekTLS(path string) ([]analyzer.FlowRecord, []analyzer.ObservationRecord, error) {
	rows, err := readZeekRows(path)
	if err != nil {
		return nil, nil, err
	}
	flows := []analyzer.FlowRecord{}
	observations := []analyzer.ObservationRecord{}
	for _, row := range rows {
		sni := firstNonEmptyString(row["server_name"], row["sni"])
		flow := analyzer.FlowRecord{
			Timestamp:           zeekTime(row["ts"]),
			FlowKey:             firstNonEmptyString(row["uid"], sensorFlowKey(row["ts"], row["id.orig_h"], sni)),
			SrcIP:               row["id.orig_h"],
			SrcPort:             uint16FromString(row["id.orig_p"]),
			DstIP:               row["id.resp_h"],
			DstPort:             uint16FromString(firstNonEmptyString(row["id.resp_p"], "443")),
			Protocol:            "tcp",
			AppProtocol:         "tls",
			SNI:                 sni,
			Direction:           securityDirection(row["id.orig_h"], row["id.resp_h"]),
			ObservedDestination: firstNonEmptyString(sni, row["id.resp_h"]),
		}
		flows = append(flows, flow)
		observations = append(observations, observationFromFlow(flow, "tls_sni"))
	}
	return flows, observations, nil
}

func observationFromFlow(flow analyzer.FlowRecord, kind string) analyzer.ObservationRecord {
	return analyzer.ObservationRecord{
		Timestamp:           flow.Timestamp,
		Kind:                kind,
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
}

func readZeekRows(path string) ([]map[string]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	fields := []string{}
	rows := []map[string]string{}
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#fields") {
			fields = strings.Fields(strings.TrimPrefix(line, "#fields"))
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		// Zeek writes one JSON object per line with LogAscii::use_json=T.
		if strings.HasPrefix(line, "{") {
			// Malformed (for example truncated) JSON lines are skipped.
			if row, err := zeekJSONRow(line); err == nil {
				rows = append(rows, row)
			}
			continue
		}
		values := strings.Split(line, "\t")
		if len(fields) == 0 {
			values = strings.Fields(line)
			fields = defaultZeekFields(len(values))
		}
		row := map[string]string{}
		for idx, field := range fields {
			if idx < len(values) {
				row[field] = zeekValue(values[idx])
			}
		}
		rows = append(rows, row)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return rows, nil
}

// zeekJSONRow flattens a Zeek JSON log record into the same field map the TSV
// reader produces; keys are already dotted ("id.orig_h") in Zeek JSON output.
func zeekJSONRow(line string) (map[string]string, error) {
	dec := json.NewDecoder(strings.NewReader(line))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	row := map[string]string{}
	for key, value := range raw {
		row[key] = zeekJSONValue(value)
	}
	return row, nil
}

func zeekJSONValue(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return zeekValue(v)
	case json.Number:
		return v.String()
	case bool:
		if v {
			return "T"
		}
		return "F"
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, zeekJSONValue(item))
		}
		return strings.Join(parts, ",")
	default:
		data, _ := json.Marshal(v)
		return string(data)
	}
}

func defaultZeekFields(count int) []string {
	base := []string{"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service"}
	if count <= len(base) {
		return base[:count]
	}
	for len(base) < count {
		base = append(base, fmt.Sprintf("field_%d", len(base)))
	}
	return base
}

func zeekValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "-" || value == "(empty)" {
		return ""
	}
	return value
}

func zeekTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	if seconds, err := strconv.ParseFloat(value, 64); err == nil {
		whole := int64(seconds)
		nanos := int64((seconds - float64(whole)) * 1e9)
		return time.Unix(whole, nanos).UTC()
	}
	return parseSensorTimestamp(value)
}

func uint16FromString(value string) uint16 {
	n, _ := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	return uint16(n)
}

func intFromString(value string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(value))
	return n
}

func int64FromString(value string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return n
}
