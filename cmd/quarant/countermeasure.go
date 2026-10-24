package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/gopacket/pcapgo"

	"quarant/internal/countermeasure"
)

// quarant countermeasure: simulate gateway countermeasures on a capture
// (internal/countermeasure).
//
//	plan    derive the gateway rules from a run's events.jsonl (Quarant),
//	        or write the rule of a baseline condition (--condition)
//	learn   learn an allowlist (each IoT device's internet destinations)
//	        from captures of a learning period
//	filter  write the capture without the packets the chosen rules stop
//
// The filtered capture is analysed like any other; comparing the runs shows
// which evidence the countermeasures remove.
func runCountermeasure(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("countermeasure requires subcommand: plan, learn or filter")
	}
	switch args[0] {
	case "plan":
		return runCountermeasurePlan(args[1:], out)
	case "learn":
		return runCountermeasureLearn(args[1:], out)
	case "filter":
		return runCountermeasureFilter(args[1:], out)
	default:
		return fmt.Errorf("unknown countermeasure subcommand %q; use plan, learn or filter", args[0])
	}
}

func runCountermeasurePlan(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("countermeasure plan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	events := fs.String("events", "", "events.jsonl of the run (quarant analyze or quarant merge)")
	outPath := fs.String("out", "", "plan JSON output")
	inventory := fs.String("inventory", "", "device_inventory.json, to name devices by MAC (default: next to --events)")
	fs.String("condition", "quarant", "quarant (rules from --events) or a baseline: router_default, isolate_iot, block_cleartext_ports")
	emapPath := fs.String("evidence-map", "", "evidence-map.json: make rules only from events that are evidence of a violation")
	planNonIoT := fs.String("non-iot-macs", "", "file listing the MACs of home hosts that are not IoT devices (no rules for them)")
	localNets := fs.String("local-net", "", "comma-separated CIDRs of the home network (default: RFC1918, link-local and ULA ranges)")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse countermeasure plan flags: %w", err)
	}
	condition := fs.Lookup("condition").Value.String()
	if fs.NArg() != 0 || *outPath == "" || (condition == "quarant" && *events == "") {
		return fmt.Errorf("usage: quarant countermeasure plan (--events events.jsonl | --condition %s|%s|%s) --out plan.json [--local-net CIDRS]",
			countermeasure.RouterDefault, countermeasure.IsolateIoT, countermeasure.BlockCleartextPorts)
	}
	if condition != "quarant" {
		rules, err := countermeasure.Baseline(condition)
		if err != nil {
			return err
		}
		if err := writePrettyJSON(*outPath, map[string]any{"condition": condition, "rules": rules}); err != nil {
			return err
		}
		fmt.Fprintf(out, "Countermeasure plan: condition=%s out=%s\n", condition, *outPath)
		return nil
	}
	local, err := parseLocalNetsFlag(*localNets)
	if err != nil {
		return err
	}
	evs, err := loadAnalyzerEvents(*events)
	if err != nil {
		return err
	}
	inv := *inventory
	if inv == "" {
		inv = filepath.Join(filepath.Dir(*events), "device_inventory.json")
	}
	macs := map[string]string{}
	var invDoc struct {
		Devices []struct {
			IP  string `json:"ip"`
			MAC string `json:"mac_address"`
		} `json:"devices"`
	}
	if err := readJSONFileLocal(inv, &invDoc); err == nil {
		for _, d := range invDoc.Devices {
			macs[d.IP] = d.MAC
		}
	} else if *inventory != "" {
		return err
	}
	var opts countermeasure.PlanOptions
	if *emapPath != "" {
		m, err := countermeasure.LoadEvidenceMap(*emapPath)
		if err != nil {
			return err
		}
		opts.Counts = m.Counts
	}
	if *planNonIoT != "" {
		list, err := readMACList(*planNonIoT)
		if err != nil {
			return err
		}
		opts.NonIoT = map[string]bool{}
		for _, m := range list {
			opts.NonIoT[m] = true
		}
	}
	rules := countermeasure.Plan(evs, local, func(ip string) string { return macs[ip] }, opts)
	if err := writePrettyJSON(*outPath, map[string]any{"source_events": *events, "rules": rules}); err != nil {
		return err
	}
	counts := map[string]int{}
	for _, r := range rules {
		counts[r.Countermeasure]++
	}
	fmt.Fprintf(out, "Countermeasure plan: rules=%d out=%s\n", len(rules), *outPath)
	for _, c := range countermeasure.Countermeasures {
		fmt.Fprintf(out, "  %-24s %d\n", c, counts[c])
	}
	return nil
}

func runCountermeasureFilter(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("countermeasure filter", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	planPath := fs.String("plan", "", "plan JSON from quarant countermeasure plan")
	chosen := fs.String("apply", strings.Join([]string{countermeasure.BlockInbound, countermeasure.BlockWeakDestinations, countermeasure.Isolate}, ","), "comma-separated countermeasures to simulate")
	nonIoT := fs.String("non-iot-macs", "", "file listing the MACs of home hosts that are not IoT devices (one per line, # comments)")
	gateways := fs.String("gateway", "", "comma-separated gateway addresses (isolation keeps them reachable)")
	outPath := fs.String("out", "", "filtered capture output (pcap); - writes to stdout, so the capture can be analysed without storing it")
	statsPath := fs.String("stats", "", "where to write the filter statistics (default: next to --out or in --out-dir)")
	outDir := fs.String("out-dir", "", "write each input to its own file in this directory instead of --out (state such as DNS names carries over)")
	localNets := fs.String("local-net", "", "comma-separated CIDRs of the home network")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse countermeasure filter flags: %w", err)
	}
	inputs := fs.Args()
	if *planPath == "" || (*outPath == "") == (*outDir == "") || len(inputs) == 0 {
		return fmt.Errorf("usage: quarant countermeasure filter --plan plan.json [--apply CM,...] [--gateway IP,...] (--out filtered.pcap | --out-dir DIR) CAPTURE...")
	}
	local, err := parseLocalNetsFlag(*localNets)
	if err != nil {
		return err
	}
	var plan struct {
		Rules []countermeasure.Rule `json:"rules"`
	}
	if err := readJSONFileLocal(*planPath, &plan); err != nil {
		return err
	}
	var apply []string
	for _, c := range strings.Split(*chosen, ",") {
		if c = strings.TrimSpace(c); c != "" {
			apply = append(apply, c)
		}
	}
	// Files are read in name order, so a capture split by time (YourThings)
	// keeps its order and flow directions carry over.
	sort.Strings(inputs)
	f := countermeasure.NewFilter(plan.Rules, apply, local, strings.Split(*gateways, ","))
	if *nonIoT != "" {
		macs, err := readMACList(*nonIoT)
		if err != nil {
			return err
		}
		f.SetNonIoT(macs)
	}
	copyOne := func(in string, w *pcapgo.Writer, header bool) error {
		src, err := os.Open(in)
		if err != nil {
			return err
		}
		defer src.Close()
		if err := f.Copy(src, w, header); err != nil {
			return fmt.Errorf("%s: %w", in, err)
		}
		return nil
	}
	var stats string
	if *outDir != "" {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			return err
		}
		for _, in := range inputs {
			dst, err := os.Create(filepath.Join(*outDir, filepath.Base(in)))
			if err != nil {
				return err
			}
			err = copyOne(in, pcapgo.NewWriter(dst), true)
			if cerr := dst.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		}
		stats = filepath.Join(*outDir, "filter.stats.json")
	} else {
		var dst io.WriteCloser = os.Stdout
		if *outPath != "-" {
			f, err := os.Create(*outPath)
			if err != nil {
				return err
			}
			dst = f
		}
		defer dst.Close()
		bw := bufio.NewWriterSize(dst, 1<<20)
		defer bw.Flush()
		w := pcapgo.NewWriter(bw)
		for i, in := range inputs {
			if err := copyOne(in, w, i == 0); err != nil {
				return err
			}
		}
		stats = filepath.Join(filepath.Dir(*outPath), strings.TrimSuffix(filepath.Base(*outPath), filepath.Ext(*outPath))+".stats.json")
	}
	if *statsPath != "" {
		stats = *statsPath
	} else if *outPath == "-" {
		stats = ""
	}
	f.Finish()
	if stats != "" {
		if err := writePrettyJSON(stats, map[string]any{"apply": apply, "inputs": len(inputs), "stats": f.Stats}); err != nil {
			return err
		}
	}
	if *outPath == "-" {
		// stdout carries the capture; the summary goes to stderr.
		out = os.Stderr
	}
	fmt.Fprintf(out, "Countermeasure filter: apply=%s packets=%d dropped=%d flows_blocked=%d out=%s%s\n",
		strings.Join(apply, ","), f.Stats.Packets, f.Stats.Dropped, f.Stats.FlowsBlocked, *outPath, *outDir)
	return nil
}

func runCountermeasureLearn(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("countermeasure learn", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	outPath := fs.String("out", "", "allowlist plan JSON output")
	gateways := fs.String("gateway", "", "comma-separated gateway addresses")
	nonIoT := fs.String("non-iot-macs", "", "file listing the MACs of home hosts that are not IoT devices")
	localNets := fs.String("local-net", "", "comma-separated CIDRs of the home network")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse countermeasure learn flags: %w", err)
	}
	inputs := fs.Args()
	if *outPath == "" || len(inputs) == 0 {
		return fmt.Errorf("usage: quarant countermeasure learn --out allow.json [--gateway IP,...] [--non-iot-macs FILE] CAPTURE...")
	}
	local, err := parseLocalNetsFlag(*localNets)
	if err != nil {
		return err
	}
	l := countermeasure.NewLearner(local, strings.Split(*gateways, ","))
	if *nonIoT != "" {
		macs, err := readMACList(*nonIoT)
		if err != nil {
			return err
		}
		l.SetNonIoT(macs)
	}
	sort.Strings(inputs)
	for _, in := range inputs {
		src, err := os.Open(in)
		if err != nil {
			return err
		}
		err = l.Copy(src, pcapgo.NewWriter(io.Discard), true)
		src.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", in, err)
		}
	}
	rules := l.AllowlistRules()
	devices := map[string]bool{}
	for _, r := range rules {
		devices[r.DeviceMAC] = true
	}
	if err := writePrettyJSON(*outPath, map[string]any{"condition": countermeasure.Allowlist, "learned_from": len(inputs), "rules": rules}); err != nil {
		return err
	}
	fmt.Fprintf(out, "Countermeasure learn: devices=%d entries=%d out=%s\n", len(devices), len(rules), *outPath)
	return nil
}

// readMACList reads one MAC per line; blank lines and # comments are
// skipped.
func readMACList(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line != "" {
			out = append(out, strings.ToLower(line))
		}
	}
	return out, nil
}
