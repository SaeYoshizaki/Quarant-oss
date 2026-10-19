package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"quarant/analyzer"
	"quarant/internal/corroborate"
)

// quarant merge: overlay a `quarant analyze` run with the evidence other
// analysers produced from the same capture (`quarant zeek evidence`,
// `quarant suricata evidence`), connection by connection
// (internal/corroborate). The output directory gets events.jsonl (the
// evidence, each event with its sources), uncorroborated.jsonl (the other
// analysers' low-confidence events Quarant did not report),
// merge_summary.json and a copy of Quarant's device_inventory.json, so the
// evidence-map scripts read it like any run.
func runMergeCLI(args []string, out io.Writer) error {
	return runMerge("merge", args, out)
}

// quarant zeek merge: the same, kept for the Zeek-only form (D25).
func runZeekMergeCLI(args []string, out io.Writer) error {
	return runMerge("zeek merge", args, out)
}

func runMerge(name string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	qDir := fs.String("quarant", "", "output directory of quarant analyze")
	zDir := fs.String("zeek", "", "output directory of quarant zeek evidence")
	sDir := fs.String("suricata", "", "output directory of quarant suricata evidence")
	outDir := fs.String("out", "", "output directory")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse %s flags: %w", name, err)
	}
	if fs.NArg() != 0 || *qDir == "" || *outDir == "" || (*zDir == "" && *sDir == "") {
		return fmt.Errorf("usage: quarant merge --quarant DIR [--zeek DIR] [--suricata DIR] --out DIR")
	}
	read := func(dir string) ([]analyzer.Event, error) {
		p := filepath.Join(dir, "events.jsonl")
		if _, err := os.Stat(p); err != nil {
			return nil, err
		}
		return loadAnalyzerEvents(p)
	}
	qEvents, err := read(*qDir)
	if err != nil {
		return err
	}
	var others []analyzer.Event
	counts := map[string]int{}
	for _, src := range []struct{ name, dir string }{{"zeek", *zDir}, {"suricata", *sDir}} {
		if src.dir == "" {
			continue
		}
		evs, err := read(src.dir)
		if err != nil {
			return err
		}
		counts[src.name] = len(evs)
		others = append(others, evs...)
	}
	res := corroborate.Merge(qEvents, others)
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	if err := writeJSONL(filepath.Join(*outDir, "events.jsonl"), res.Events); err != nil {
		return err
	}
	if err := writeJSONL(filepath.Join(*outDir, "uncorroborated.jsonl"), res.Held); err != nil {
		return err
	}
	summary, err := json.MarshalIndent(res.Counts, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*outDir, "merge_summary.json"), append(summary, '\n'), 0o644); err != nil {
		return err
	}
	if inv, err := os.ReadFile(filepath.Join(*qDir, "device_inventory.json")); err == nil {
		if err := os.WriteFile(filepath.Join(*outDir, "device_inventory.json"), inv, 0o644); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	fmt.Fprintf(out, "Merge: quarant=%d zeek=%d suricata=%d events=%d held=%d out=%s\n", len(qEvents), counts["zeek"], counts["suricata"], len(res.Events), len(res.Held), *outDir)
	types := make([]string, 0, len(res.Counts))
	for t, c := range res.Counts {
		if c.Both+c.OtherOnly+c.OtherHeld > 0 {
			types = append(types, t)
		}
	}
	sort.Strings(types)
	fmt.Fprintf(out, "  %-34s %7s %7s %7s %7s\n", "type", "both", "quarant", "other", "held")
	for _, t := range types {
		c := res.Counts[t]
		fmt.Fprintf(out, "  %-34s %7d %7d %7d %7d\n", t, c.Both, c.QuarantOnly, c.OtherOnly, c.OtherHeld)
	}
	return nil
}
