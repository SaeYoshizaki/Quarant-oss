package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"quarant/internal/corroborate"
)

// quarant zeek merge: overlay a `quarant analyze` run with a `quarant zeek
// evidence` run of the same capture, connection by connection
// (internal/corroborate). The output directory gets events.jsonl (the
// evidence, each event with its sources), uncorroborated.jsonl (Zeek's
// name-only matches Quarant did not report), merge_summary.json and a copy
// of Quarant's device_inventory.json, so the evidence-map scripts read it
// like any run.
func runZeekMergeCLI(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("zeek merge", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	qDir := fs.String("quarant", "", "output directory of quarant analyze")
	zDir := fs.String("zeek", "", "output directory of quarant zeek evidence")
	outDir := fs.String("out", "", "output directory")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse zeek merge flags: %w", err)
	}
	if fs.NArg() != 0 || *qDir == "" || *zDir == "" || *outDir == "" {
		return fmt.Errorf("usage: quarant zeek merge --quarant DIR --zeek DIR --out DIR")
	}
	read := func(dir string) (string, error) {
		p := filepath.Join(dir, "events.jsonl")
		_, err := os.Stat(p)
		return p, err
	}
	qPath, err := read(*qDir)
	if err != nil {
		return err
	}
	zPath, err := read(*zDir)
	if err != nil {
		return err
	}
	qEvents, err := loadAnalyzerEvents(qPath)
	if err != nil {
		return err
	}
	zEvents, err := loadAnalyzerEvents(zPath)
	if err != nil {
		return err
	}
	res := corroborate.Merge(qEvents, zEvents)
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

	fmt.Fprintf(out, "Zeek merge: quarant=%d zeek=%d events=%d held=%d out=%s\n", len(qEvents), len(zEvents), len(res.Events), len(res.Held), *outDir)
	types := make([]string, 0, len(res.Counts))
	for t, c := range res.Counts {
		if c.Both+c.OtherOnly+c.OtherHeld > 0 {
			types = append(types, t)
		}
	}
	sort.Strings(types)
	fmt.Fprintf(out, "  %-34s %7s %7s %7s %7s\n", "type", "both", "quarant", "zeek", "held")
	for _, t := range types {
		c := res.Counts[t]
		fmt.Fprintf(out, "  %-34s %7d %7d %7d %7d\n", t, c.Both, c.QuarantOnly, c.OtherOnly, c.OtherHeld)
	}
	return nil
}
