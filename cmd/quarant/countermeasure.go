package main

import (
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
//	plan    derive the gateway rules from a run's events.jsonl
//	filter  write the capture without the packets the chosen rules stop
//
// The filtered capture is analysed like any other; comparing the runs shows
// which evidence the countermeasures remove.
func runCountermeasure(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("countermeasure requires subcommand: plan or filter")
	}
	switch args[0] {
	case "plan":
		return runCountermeasurePlan(args[1:], out)
	case "filter":
		return runCountermeasureFilter(args[1:], out)
	default:
		return fmt.Errorf("unknown countermeasure subcommand %q; use plan or filter", args[0])
	}
}

func runCountermeasurePlan(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("countermeasure plan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	events := fs.String("events", "", "events.jsonl of the run (quarant analyze or quarant merge)")
	outPath := fs.String("out", "", "plan JSON output")
	inventory := fs.String("inventory", "", "device_inventory.json, to name devices by MAC (default: next to --events)")
	localNets := fs.String("local-net", "", "comma-separated CIDRs of the home network (default: RFC1918, link-local and ULA ranges)")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse countermeasure plan flags: %w", err)
	}
	if fs.NArg() != 0 || *events == "" || *outPath == "" {
		return fmt.Errorf("usage: quarant countermeasure plan --events events.jsonl --out plan.json [--local-net CIDRS]")
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
	rules := countermeasure.Plan(evs, local, func(ip string) string { return macs[ip] })
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
	chosen := fs.String("apply", strings.Join(countermeasure.Countermeasures, ","), "comma-separated countermeasures to simulate")
	gateways := fs.String("gateway", "", "comma-separated gateway addresses (isolation keeps them reachable)")
	outPath := fs.String("out", "", "filtered capture output (pcap)")
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
		dst, err := os.Create(*outPath)
		if err != nil {
			return err
		}
		defer dst.Close()
		w := pcapgo.NewWriter(dst)
		for i, in := range inputs {
			if err := copyOne(in, w, i == 0); err != nil {
				return err
			}
		}
		stats = filepath.Join(filepath.Dir(*outPath), strings.TrimSuffix(filepath.Base(*outPath), filepath.Ext(*outPath))+".stats.json")
	}
	if err := writePrettyJSON(stats, map[string]any{"apply": apply, "inputs": len(inputs), "stats": f.Stats}); err != nil {
		return err
	}
	fmt.Fprintf(out, "Countermeasure filter: apply=%s packets=%d dropped=%d flows_blocked=%d out=%s%s\n",
		strings.Join(apply, ","), f.Stats.Packets, f.Stats.Dropped, f.Stats.FlowsBlocked, *outPath, *outDir)
	return nil
}
