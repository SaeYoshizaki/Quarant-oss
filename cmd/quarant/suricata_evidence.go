package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"quarant/internal/suricataevidence"
)

// quarant suricata evidence: Suricata's alerts in eve.json become
// per-device events (internal/suricataevidence), in the same shape as
// `quarant analyze`, for `quarant merge`.
func runSuricataEvidenceCLI(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("suricata evidence", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	evePath := fs.String("eve", "", "Suricata eve.json")
	outDir := fs.String("out", "", "output directory (events.jsonl)")
	localNets := fs.String("local-net", "", "comma-separated CIDRs of the monitored network (default: RFC1918, link-local and ULA ranges)")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse suricata evidence flags: %w", err)
	}
	if fs.NArg() != 0 || *evePath == "" || *outDir == "" {
		return fmt.Errorf("usage: quarant suricata evidence --eve eve.json --out DIR [--local-net CIDRS]")
	}
	local, err := parseLocalNetsFlag(*localNets)
	if err != nil {
		return err
	}
	f, err := os.Open(*evePath)
	if err != nil {
		return err
	}
	capture, err := suricataevidence.Read(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("read %s: %w", *evePath, err)
	}
	res := suricataevidence.Convert(capture, local)
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	if err := writeJSONL(filepath.Join(*outDir, "events.jsonl"), res.Events); err != nil {
		return err
	}
	counts := map[string]int{}
	for _, e := range res.Events {
		counts[e.Type]++
	}
	fmt.Fprintf(out, "Suricata evidence: alerts=%d events=%d skipped_records=%d out=%s\n", len(capture.Alerts), len(res.Events), capture.SkippedRecords, *outDir)
	printCounts(out, counts)
	if len(res.Ignored) > 0 {
		fmt.Fprintln(out, "  not converted (alerts):")
		printCounts(out, res.Ignored)
	}
	return nil
}

func printCounts(out io.Writer, counts map[string]int) {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(out, "  %-34s %d\n", k, counts[k])
	}
}
