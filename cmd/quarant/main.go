package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"quarant/analyzer"
	"quarant/analyzer/knowledge"
	"quarant/internal/findings"
	"quarant/internal/reportapi"
	"quarant/internal/viewer"
)

func main() {
	log.SetFlags(log.LstdFlags)

	args := os.Args[1:]
	if len(args) == 0 {
		runLegacyCapture(nil)
		return
	}

	switch args[0] {
	case "analyze":
		if err := runAnalyze(args[1:]); err != nil {
			log.Fatal(err)
		}
	case "live":
		if err := runLive(args[1:]); err != nil {
			log.Fatal(err)
		}
	case "report":
		if err := runReport(args[1:]); err != nil {
			log.Fatal(err)
		}
	case "compare":
		if err := runCompare(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "coverage":
		if err := runCoverage(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "openwrt":
		if err := runOpenWrt(args[1:]); err != nil {
			log.Fatal(err)
		}
	case "evidence":
		if err := runEvidence(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "experiment":
		if err := runExperiment(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "suricata":
		if err := runSuricata(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "merge":
		if err := runMergeCLI(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "zeek":
		if err := runZeek(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "snort":
		if err := runSnort(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "taxonomy":
		if err := runTaxonomy(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "precision":
		if err := runPrecision(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "mitigate":
		if err := runMitigate(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "mitigation-eval":
		if err := runMitigationEval(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "attack-eval":
		if err := runAttackEval(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "research-report":
		if err := runResearchReport(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "quality-gate":
		if err := runQualityGate(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "parser-diff":
		if err := runParserDiff(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "dataset-eval":
		if err := runDatasetEval(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "devices":
		if err := runDevices(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "findings":
		if err := runFindings(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "label-eval":
		if err := runLabelEval(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "synth":
		if err := runSynth(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "eval":
		if err := runEval(args[1:], os.Stdout); err != nil {
			log.Fatal(err)
		}
	default:
		// Preserve the previous interface-driven entrypoint when called without subcommands.
		runLegacyCapture(args)
	}
}

func runCompare(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	beforeEvents := fs.String("before", "", "before events JSONL or report JSON path")
	afterEvents := fs.String("after", "", "after events JSONL or report JSON path")
	beforeFlows := fs.String("before-flows", "", "before flows JSONL path (default: sibling flows.jsonl)")
	afterFlows := fs.String("after-flows", "", "after flows JSONL path (default: sibling flows.jsonl)")
	beforeInventory := fs.String("before-inventory", "", "before inventory JSON path (default: sibling device_inventory.json)")
	afterInventory := fs.String("after-inventory", "", "after inventory JSON path (default: sibling device_inventory.json)")
	format := fs.String("format", "text", "output format: text|json")

	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse compare flags: %w", err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("compare accepts flags only; use --before and --after")
	}

	before, err := reportapi.LoadProtectionSnapshot("before", *beforeEvents, *beforeFlows, *beforeInventory)
	if err != nil {
		return fmt.Errorf("load before snapshot: %w", err)
	}
	after, err := reportapi.LoadProtectionSnapshot("after", *afterEvents, *afterFlows, *afterInventory)
	if err != nil {
		return fmt.Errorf("load after snapshot: %w", err)
	}
	comparison := reportapi.CompareProtectionSnapshots(before, after)

	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(comparison)
	case "text", "":
		printProtectionComparison(out, comparison)
		return nil
	default:
		return fmt.Errorf("unknown -format: %s (use text|json)", *format)
	}
}

func printProtectionComparison(out io.Writer, comparison reportapi.ProtectionComparison) {
	fmt.Fprintln(out, "=== Quarant Before / After Report ===")
	fmt.Fprintln(out)
	fmt.Fprintln(out, comparison.Summary)
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%-28s %10s %10s %10s %s\n", "Metric", "Before", "After", "Delta", "Result")
	fmt.Fprintf(out, "%-28s %10s %10s %10s %s\n", "------", "------", "-----", "-----", "------")
	for _, delta := range comparison.Deltas {
		result := "unchanged"
		if delta.Delta != 0 {
			if delta.Improved {
				result = "improved"
			} else {
				result = "regressed"
			}
		}
		fmt.Fprintf(out, "%-28s %10d %10d %+10d %s\n", delta.Label, delta.Before, delta.After, delta.Delta, result)
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "Improved: %d  Regressed: %d  Unchanged: %d\n", comparison.ImprovedCount, comparison.RegressedCount, comparison.UnchangedCount)
}

func runAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	flags := bindCaptureFlags(fs, captureFlagDefaults{
		outPath:          "events.jsonl",
		allowIface:       false,
		reportHelp:       "launch the local report viewer while analysis is running",
		appendHelp:       "append to existing events/flows outputs instead of replacing them",
		flowsHelp:        "path to write flow summaries JSONL (default: sibling flows.jsonl)",
		observationsHelp: "path to write passive observation JSONL (default: sibling observations.jsonl, empty to disable with --observations-out=-)",
		inventoryHelp:    "path to write device inventory snapshot JSON (default: sibling device_inventory.json, empty to disable with --inventory-out=-)",
	})
	findingsOut := fs.String("findings-out", "", "path to write the per-device findings summary JSON (default: sibling findings.json, - to disable)")

	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse analyze flags: %w", err)
	}

	localNets, err := parseLocalNetsFlag(*flags.localNets)
	if err != nil {
		return err
	}

	inputPath := "-"
	if fs.NArg() > 0 {
		inputPath = fs.Arg(0)
	}
	if fs.NArg() > 1 {
		return fmt.Errorf("analyze accepts exactly one input path or - for stdin")
	}

	cfg := buildAnalysisConfig(inputPath, "", flags)
	cfg.LocalNetworks = localNets
	if err := runCapture(cfg, func(engine *analyzer.Engine) error {
		if cfg.InputPath == "-" {
			return engine.RunPCAPStream(os.Stdin)
		}
		return engine.RunOffline(cfg.InputPath)
	}); err != nil {
		return err
	}
	// The summary is written once the capture is fully analysed and the
	// sinks are closed; events.jsonl stays the raw record.
	if *findingsOut == "-" {
		return nil
	}
	eventsDir := filepath.Dir(cfg.EventsOut)
	if eventsDir == "." {
		eventsDir = ""
	}
	_, err = findings.WriteFromRun(cfg.EventsOut, cfg.InventoryOut, defaultSibling(*findingsOut, eventsDir, "findings.json"), "WARNING")
	return err
}

func runLive(args []string) error {
	fs := flag.NewFlagSet("live", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	flags := bindCaptureFlags(fs, captureFlagDefaults{
		outPath:          "events.jsonl",
		iface:            "eth0",
		allowIface:       true,
		reportHelp:       "launch the local report viewer while capture is running",
		appendHelp:       "append to existing events/flows outputs instead of replacing them",
		flowsHelp:        "path to write flow summaries JSONL (default: sibling flows.jsonl)",
		observationsHelp: "path to write passive observation JSONL (default: sibling observations.jsonl, empty to disable with --observations-out=-)",
		inventoryHelp:    "path to write device inventory snapshot JSON (default: sibling device_inventory.json, empty to disable with --inventory-out=-)",
	})

	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse live flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("live does not accept positional arguments")
	}
	if strings.TrimSpace(*flags.iface) == "" {
		return fmt.Errorf("live requires --iface")
	}
	localNets, err := parseLocalNetsFlag(*flags.localNets)
	if err != nil {
		return err
	}

	cfg := buildAnalysisConfig("", *flags.iface, flags)
	cfg.LocalNetworks = localNets
	// Stop on Ctrl-C / SIGTERM so open flows and behaviour findings are
	// flushed before the outputs are closed.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runCapture(cfg, func(engine *analyzer.Engine) error {
		return engine.RunLiveContext(ctx, cfg.Interface)
	})
}

func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	openViewer := fs.Bool("open", false, "open the local report viewer in a browser")
	demoMode := fs.Bool("demo", false, "use bundled demo data from examples/demo")
	addr := fs.String("addr", "127.0.0.1:8080", "HTTP listen address")
	webDist := fs.String("web-dist", filepath.Join("web", "out"), "path to exported web UI assets")
	flowsPath := fs.String("flows-in", "", "input flows JSONL path (default: sibling flows.jsonl)")
	observationsPath := fs.String("observations-in", "", "input passive observations JSONL path (default: sibling observations.jsonl)")
	inventoryPath := fs.String("inventory-in", "", "input inventory JSON path (default: sibling device_inventory.json)")

	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse report flags: %w", err)
	}
	if *demoMode {
		if fs.NArg() > 0 {
			return fmt.Errorf("report --demo does not accept an input path")
		}
		demoDir := filepath.Join("examples", "demo")
		return viewer.Serve(viewer.Options{
			EventsPath:       filepath.Join(demoDir, "events.jsonl"),
			FlowsPath:        defaultSibling(*flowsPath, demoDir, "flows.jsonl"),
			ObservationsPath: defaultSibling(*observationsPath, demoDir, "observations.jsonl"),
			InventoryPath:    defaultSibling(*inventoryPath, demoDir, "device_inventory.json"),
			Addr:             *addr,
			OpenBrowser:      *openViewer,
			WebDist:          *webDist,
			DemoMode:         true,
		})
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("report requires exactly one input path: events.jsonl or report.json")
	}

	inputPath := fs.Arg(0)
	dir := filepath.Dir(inputPath)
	if dir == "." {
		dir = ""
	}

	opts := viewer.Options{
		Addr:             *addr,
		OpenBrowser:      *openViewer,
		WebDist:          *webDist,
		FlowsPath:        defaultSibling(*flowsPath, dir, "flows.jsonl"),
		ObservationsPath: defaultSibling(*observationsPath, dir, "observations.jsonl"),
		InventoryPath:    defaultSibling(*inventoryPath, dir, "device_inventory.json"),
	}
	if strings.EqualFold(filepath.Ext(inputPath), ".json") {
		opts.ReportPath = inputPath
		opts.EventsPath = defaultSibling("", dir, "events.jsonl")
	} else {
		opts.EventsPath = inputPath
	}
	return viewer.Serve(opts)
}

type analysisConfig struct {
	InputPath         string
	Interface         string
	EventsOut         string
	FlowsOut          string
	ObservationsOut   string
	InventoryOut      string
	InventoryInterval time.Duration
	Debug             bool
	AppendOutput      bool
	Report            bool
	OpenViewer        bool
	ViewerAddr        string
	WebDist           string
	BlockOnViewer     bool
	LocalNetworks     analyzer.LocalNetworks
	IdentityState     string
}

type captureRunner func(*analyzer.Engine) error

type captureFlags struct {
	outPath           *string
	flowsOutPath      *string
	observationsOut   *string
	inventoryOut      *string
	inventoryInterval *time.Duration
	identityState     *string
	debug             *bool
	appendOutput      *bool
	report            *bool
	openViewer        *bool
	addr              *string
	webDist           *string
	iface             *string
	localNets         *string
}

type captureFlagDefaults struct {
	outPath          string
	iface            string
	allowIface       bool
	appendHelp       string
	reportHelp       string
	flowsHelp        string
	observationsHelp string
	inventoryHelp    string
}

func bindCaptureFlags(fs *flag.FlagSet, defaults captureFlagDefaults) captureFlags {
	outDefault := defaults.outPath
	if strings.TrimSpace(outDefault) == "" {
		outDefault = "events.jsonl"
	}
	flags := captureFlags{
		outPath:           fs.String("out", outDefault, "path to write events JSONL"),
		flowsOutPath:      fs.String("flows-out", "", defaults.flowsHelp),
		observationsOut:   fs.String("observations-out", "", defaults.observationsHelp),
		inventoryOut:      fs.String("inventory-out", "", defaults.inventoryHelp),
		inventoryInterval: fs.Duration("inventory-interval", 10*time.Second, "interval to refresh device inventory snapshot JSON"),
		debug:             fs.Bool("debug", false, "enable debug payload logging"),
		appendOutput:      fs.Bool("append", false, defaults.appendHelp),
		report:            fs.Bool("report", false, defaults.reportHelp),
		openViewer:        fs.Bool("open", false, "open the local report viewer in a browser"),
		addr:              fs.String("addr", "127.0.0.1:8080", "HTTP listen address for the report viewer"),
		webDist:           fs.String("web-dist", filepath.Join("web", "out"), "path to exported web UI assets"),
		identityState:     fs.String("identity-state", "", "JSON file of what each MAC announced about itself (DHCP, mDNS, SSDP); loaded before the capture if it exists and saved after it, so later captures keep earlier self-descriptions"),
		localNets:         fs.String("local-net", "", "comma-separated CIDRs of the monitored network; only hosts inside are tracked as devices (default: RFC1918, link-local and ULA ranges)"),
	}
	if defaults.allowIface {
		ifaceDefault := defaults.iface
		if strings.TrimSpace(ifaceDefault) == "" {
			ifaceDefault = "eth0"
		}
		flags.iface = fs.String("iface", ifaceDefault, "capture interface")
	}
	return flags
}

func parseLocalNetsFlag(value string) (analyzer.LocalNetworks, error) {
	return analyzer.ParseLocalNetworks(strings.Split(value, ","))
}

func buildAnalysisConfig(inputPath, iface string, flags captureFlags) analysisConfig {
	eventsDir := filepath.Dir(*flags.outPath)
	if eventsDir == "." {
		eventsDir = ""
	}
	flowsPath := defaultSibling(*flags.flowsOutPath, eventsDir, "flows.jsonl")
	observationsPath := defaultSibling(*flags.observationsOut, eventsDir, "observations.jsonl")
	inventoryPath := defaultSibling(*flags.inventoryOut, eventsDir, "device_inventory.json")
	if *flags.observationsOut == "-" {
		observationsPath = ""
	}
	if *flags.inventoryOut == "-" {
		inventoryPath = ""
	}
	return analysisConfig{
		InputPath:         inputPath,
		Interface:         iface,
		EventsOut:         *flags.outPath,
		FlowsOut:          flowsPath,
		ObservationsOut:   observationsPath,
		InventoryOut:      inventoryPath,
		InventoryInterval: *flags.inventoryInterval,
		Debug:             *flags.debug,
		AppendOutput:      *flags.appendOutput,
		Report:            *flags.report,
		OpenViewer:        *flags.openViewer,
		ViewerAddr:        *flags.addr,
		WebDist:           *flags.webDist,
		BlockOnViewer:     inputPath != "",
		IdentityState:     *flags.identityState,
	}
}

func runCapture(cfg analysisConfig, runner captureRunner) error {
	if runner == nil {
		return fmt.Errorf("capture runner is required")
	}

	runtime, err := newAnalysisRuntime(cfg)
	if err != nil {
		return err
	}
	defer runtime.close()

	if cfg.Report {
		runtime.startViewer()
	}
	if err := runner(runtime.engine); err != nil {
		return err
	}
	if cfg.Report && cfg.BlockOnViewer {
		return runtime.waitForViewer()
	}
	return nil
}

func analyzePCAP(cfg analysisConfig) error {
	return runCapture(cfg, func(engine *analyzer.Engine) error {
		if cfg.InputPath == "-" {
			return engine.RunPCAPStream(os.Stdin)
		}
		return engine.RunOffline(cfg.InputPath)
	})
}

type analysisRuntime struct {
	engine          *analyzer.Engine
	handler         *analyzer.FlowHandler
	eventSink       *analyzer.JSONLSink
	flowSink        *analyzer.JSONLSink
	observationSink *analyzer.JSONLSink
	inventoryWriter *analyzer.DeviceInventoryWriter
	viewerOnce      sync.Once
	viewerErr       chan error
	cfg             analysisConfig
}

func newAnalysisRuntime(cfg analysisConfig) (*analysisRuntime, error) {
	if strings.TrimSpace(cfg.EventsOut) == "" {
		return nil, fmt.Errorf("events output path is required")
	}
	if strings.TrimSpace(cfg.FlowsOut) == "" {
		return nil, fmt.Errorf("flows output path is required")
	}
	if !cfg.AppendOutput {
		if err := resetOutputFile(cfg.EventsOut); err != nil {
			return nil, err
		}
		if err := resetOutputFile(cfg.FlowsOut); err != nil {
			return nil, err
		}
		if err := resetOutputFile(cfg.ObservationsOut); err != nil {
			return nil, err
		}
	}

	db, err := knowledge.LoadAll()
	if err != nil {
		return nil, fmt.Errorf("load knowledge db: %w", err)
	}

	log.Printf(
		"knowledge db loaded: categories=%d communication_types=%d pii_types=%d policies=%d inference_categories=%d behavior_baselines=%d i5_vulnerable_components=%d",
		len(db.DeviceCategories.Categories),
		len(db.CommunicationTypes.CommunicationTypes),
		len(db.PIITypes.PIITypes),
		len(db.CategoryPolicy),
		len(db.CategoryInference.Categories),
		len(db.BehaviorBaselines)-1,
		len(*db.I5Vulnerable),
	)

	sink, err := analyzer.NewJSONSink(cfg.EventsOut)
	if err != nil {
		return nil, err
	}

	flowSink, err := analyzer.NewJSONSink(cfg.FlowsOut)
	if err != nil {
		_ = sink.Close()
		return nil, err
	}

	var observationSink *analyzer.JSONLSink
	if cfg.ObservationsOut != "" {
		observationSink, err = analyzer.NewJSONSink(cfg.ObservationsOut)
		if err != nil {
			_ = flowSink.Close()
			_ = sink.Close()
			return nil, err
		}
	}

	handler := analyzer.NewFlowHandlerWithObservations(sink, flowSink, observationSink, cfg.Debug, db)
	handler.SetLocalNetworks(cfg.LocalNetworks)
	if err := loadIdentityState(cfg.IdentityState, handler); err != nil {
		_ = flowSink.Close()
		_ = sink.Close()
		if observationSink != nil {
			_ = observationSink.Close()
		}
		return nil, err
	}
	var inventoryWriter *analyzer.DeviceInventoryWriter
	if cfg.InventoryOut != "" {
		inventoryWriter = analyzer.NewDeviceInventoryWriter(cfg.InventoryOut, cfg.InventoryInterval, handler.DeviceInventory)
		inventoryWriter.Start()
	}

	return &analysisRuntime{
		engine:          analyzer.NewEngine(handler),
		handler:         handler,
		eventSink:       sink,
		flowSink:        flowSink,
		observationSink: observationSink,
		inventoryWriter: inventoryWriter,
		viewerErr:       make(chan error, 1),
		cfg:             cfg,
	}, nil
}

func (r *analysisRuntime) startViewer() {
	r.viewerOnce.Do(func() {
		go func() {
			r.viewerErr <- viewer.Serve(viewer.Options{
				EventsPath:       r.cfg.EventsOut,
				FlowsPath:        r.cfg.FlowsOut,
				ObservationsPath: r.cfg.ObservationsOut,
				InventoryPath:    r.cfg.InventoryOut,
				Addr:             r.cfg.ViewerAddr,
				OpenBrowser:      r.cfg.OpenViewer,
				WebDist:          r.cfg.WebDist,
			})
		}()
	})
}

func (r *analysisRuntime) close() {
	if r == nil {
		return
	}
	if r.inventoryWriter != nil {
		r.inventoryWriter.Stop()
	}
	if err := saveIdentityState(r.cfg.IdentityState, r.handler); err != nil {
		log.Printf("warning: %v", err)
	}
	if r.flowSink != nil {
		_ = r.flowSink.Close()
	}
	if r.observationSink != nil {
		_ = r.observationSink.Close()
	}
	if r.eventSink != nil {
		_ = r.eventSink.Close()
	}
}

func (r *analysisRuntime) waitForViewer() error {
	if r == nil || !r.cfg.Report {
		return nil
	}
	return <-r.viewerErr
}

func resetOutputFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	return f.Close()
}

func defaultSibling(explicit, dir, name string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	if dir == "" {
		return name
	}
	return filepath.Join(dir, name)
}

func normalizeFlagArgs(fs *flag.FlagSet, args []string) []string {
	flagArgs := make([]string, 0, len(args))
	positionals := make([]string, 0, 1)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			positionals = append(positionals, arg)
			continue
		}
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}

		flagArgs = append(flagArgs, arg)
		name := strings.TrimLeft(arg, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		f := fs.Lookup(name)
		if f == nil || isBoolFlag(f) || strings.Contains(arg, "=") {
			continue
		}
		if i+1 < len(args) {
			flagArgs = append(flagArgs, args[i+1])
			i++
		}
	}
	return append(flagArgs, positionals...)
}

func isBoolFlag(f *flag.Flag) bool {
	type boolFlag interface {
		IsBoolFlag() bool
	}
	v, ok := f.Value.(boolFlag)
	return ok && v.IsBoolFlag()
}

func runLegacyCapture(args []string) {
	fs := flag.NewFlagSet("quarant", flag.ExitOnError)
	debug := fs.Bool("debug", false, "enable debug payload logging")
	iface := fs.String("i", "", "interface to capture on (default eth1 when -pcap is not given)")
	pcapPath := fs.String("pcap", "", "pcap file to read, or - to read pcap stream from stdin")
	inventoryOut := fs.String("inventory-out", "device_inventory.json", "path to write device inventory snapshot JSON (empty to disable)")
	inventoryInterval := fs.Duration("inventory-interval", 10*time.Second, "interval to refresh device inventory snapshot JSON")
	_ = fs.Parse(args)

	if *iface != "" && *pcapPath != "" {
		log.Fatal("use either -i <interface> or -pcap <file|->, not both")
	}
	if *iface == "" && *pcapPath == "" {
		*iface = "eth1"
	}

	cfg := analysisConfig{
		InputPath:         *pcapPath,
		Interface:         *iface,
		EventsOut:         "events.jsonl",
		FlowsOut:          "flows.jsonl",
		ObservationsOut:   "observations.jsonl",
		InventoryOut:      *inventoryOut,
		InventoryInterval: *inventoryInterval,
		Debug:             *debug,
		AppendOutput:      true,
	}
	err := runCapture(cfg, func(engine *analyzer.Engine) error {
		switch {
		case cfg.InputPath == "-":
			return engine.RunPCAPStream(os.Stdin)
		case cfg.InputPath != "":
			return engine.RunOffline(cfg.InputPath)
		default:
			return engine.RunLive(cfg.Interface)
		}
	})
	if err != nil {
		log.Fatal(err)
	}
}
