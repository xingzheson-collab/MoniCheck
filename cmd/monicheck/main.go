package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"monicheck/internal/buildinfo"
	"monicheck/internal/execution"
	"monicheck/internal/localruntime"
	"monicheck/internal/localui"
	"monicheck/internal/mcpserver"
	"monicheck/internal/report"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "local":
		os.Exit(runLocal(ctx, os.Args[2:], os.Stdout, os.Stderr))
	case "ui":
		os.Exit(runUI(ctx, os.Args[2:], os.Stdout, os.Stderr))
	case "connectors":
		os.Exit(runConnectors(os.Args[2:], os.Stdout, os.Stderr))
	case "mcp":
		os.Exit(runMCP(ctx, os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	case "version":
		os.Exit(runVersion(os.Args[2:], os.Stdout, os.Stderr))
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func runUI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "127.0.0.1:8080", "loopback address for the Local UI")
	storagePath := fs.String("storage-path", defaultStoragePath(), "completed Local or Agent audit state file")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	if err := localruntime.ValidateViewOptions(*listen, *storagePath); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	runtime, err := localruntime.OpenExisting(ctx, *storagePath)
	if err != nil {
		fmt.Fprintf(stderr, "open audit state: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "MoniCheck Agent audit UI: http://%s/ui/static/?view=agent\nState: %s\n", *listen, *storagePath)
	server := localui.New(*listen, runtime)
	if err := server.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "serve audit UI: %v\n", err)
		return 1
	}
	return 0
}

func runMCP(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	transport := fs.String("transport", "stdio", "MCP transport (stdio)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	if *transport != "stdio" {
		fmt.Fprintf(stderr, "unsupported MCP transport %q\n", *transport)
		return 2
	}
	server := mcpserver.Server{Input: stdin, Output: stdout, Errors: stderr}
	if err := server.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "run MCP server: %v\n", err)
		return 1
	}
	return 0
}

func runLocal(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	commandStartedAt := time.Now().UTC()
	fs := flag.NewFlagSet("local", flag.ContinueOnError)
	fs.SetOutput(stderr)
	opts := localruntime.Options{}
	check := false
	serveOnly := false
	format, reportOut, bundleOut := "text", "", ""
	fs.StringVar(&opts.Listen, "listen", "127.0.0.1:8080", "loopback address for the Local UI")
	fs.StringVar(&opts.StoragePath, "storage-path", defaultStoragePath(), "durable local state file")
	fs.StringVar(&opts.LogLevel, "log-level", "quiet", "quiet, debug, info, warn, or error")
	fs.StringVar(&opts.ConfigPath, "config", "", "YAML connector configuration file")
	fs.StringVar(&opts.PrometheusURL, "prometheus-url", os.Getenv("MONICHECK_PROMETHEUS_URL"), "Prometheus endpoint")
	fs.StringVar(&opts.PrometheusDatasourceUID, "prometheus-datasource-uid", os.Getenv("MONICHECK_GRAFANA_PROMETHEUS_DATASOURCE_UID"), "Grafana datasource UID bound to the Prometheus endpoint")
	fs.StringVar(&opts.GrafanaURL, "grafana-url", os.Getenv("MONICHECK_GRAFANA_URL"), "Grafana endpoint")
	fs.StringVar(&opts.AlertmanagerURL, "alertmanager-url", os.Getenv("MONICHECK_ALERTMANAGER_URL"), "Alertmanager endpoint")
	fs.StringVar(&opts.KubernetesManifest, "kubernetes-manifest", os.Getenv("MONICHECK_KUBERNETES_MANIFEST_PATH"), "manifest file or directory")
	fs.BoolVar(&check, "check", false, "scan once and exit")
	fs.BoolVar(&serveOnly, "serve-only", false, "open completed state without contacting providers or running analyzers")
	fs.StringVar(&format, "format", "text", "check output: text or json")
	fs.StringVar(&reportOut, "report-out", "", "write governance JSON to a private file")
	fs.StringVar(&bundleOut, "bundle-out", "", "write privacy-safe evidence-bundle.v1 to a private file")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	if !check && (strings.TrimSpace(reportOut) != "" || strings.TrimSpace(bundleOut) != "") {
		fmt.Fprintln(stderr, "--report-out and --bundle-out require --check")
		return 2
	}
	if serveOnly {
		if check || strings.TrimSpace(reportOut) != "" || strings.TrimSpace(bundleOut) != "" {
			fmt.Fprintln(stderr, "--serve-only cannot be combined with --check, --report-out, or --bundle-out")
			return 2
		}
		return serveExisting(ctx, opts.Listen, opts.StoragePath, stdout, stderr)
	}
	if err := localruntime.ValidateOptions(opts); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	opts.ActivationStartedAt = commandStartedAt
	scanCtx := execution.WithProgressReporter(ctx, func(event execution.ProgressEvent) {
		writeLocalProgress(stderr, event)
	})
	runtime, err := localruntime.New(scanCtx, opts)
	if err != nil {
		fmt.Fprintf(stderr, "scan failed: %v\n", err)
		return 1
	}
	regression, err := report.BuildLocalRegression(ctx, runtime.Store)
	if err != nil {
		fmt.Fprintf(stderr, "build local report: %v\n", err)
		return 1
	}
	if reportOut != "" {
		export, loadErr := runtime.LatestReport(ctx)
		if loadErr != nil || writePrivate(reportOut, export.Content) != nil {
			fmt.Fprintln(stderr, "write report failed")
			return 1
		}
	}
	if bundleOut != "" {
		bundle, buildErr := runtime.EvidenceBundle(ctx)
		if buildErr != nil {
			fmt.Fprintf(stderr, "build evidence bundle: %v\n", buildErr)
			return 1
		}
		body, encodeErr := json.MarshalIndent(bundle, "", "  ")
		if encodeErr != nil || writePrivate(bundleOut, string(append(body, '\n'))) != nil {
			fmt.Fprintln(stderr, "write evidence bundle failed")
			return 1
		}
	}
	if check {
		passed := len(regression.RegressedMetrics) == 0
		elapsed := time.Since(commandStartedAt)
		result := map[string]any{
			"contract_version": "local-policy-gate.v1", "passed": passed, "state": regression.State,
			"snapshot_count": regression.SnapshotCount, "regressed_metrics": regression.RegressedMetrics,
			"scan_elapsed_milliseconds": elapsed.Milliseconds(), "target_seconds": 900,
			"within_target": elapsed <= 15*time.Minute,
		}
		if format == "json" {
			body, _ := json.MarshalIndent(result, "", "  ")
			fmt.Fprintln(stdout, string(body))
		} else if format == "text" {
			fmt.Fprintf(stdout, "Local Coverage/Risk gate: %s\nSnapshots: %d\nRegressed: %s\n", map[bool]string{true: "PASS", false: "FAIL"}[passed], regression.SnapshotCount, strings.Join(regression.RegressedMetrics, ", "))
		} else {
			fmt.Fprintln(stderr, "--format must be text or json")
			return 2
		}
		if !passed {
			return 1
		}
		return 0
	}
	elapsed := time.Since(commandStartedAt)
	fmt.Fprintf(stderr, "First report ready in %s (%s 15m target).\n", localDuration(elapsed), map[bool]string{true: "within", false: "over"}[elapsed <= 15*time.Minute])
	fmt.Fprintf(stdout, "MoniCheck Local UI: http://%s/ui/static/\nState: %s\n", opts.Listen, opts.StoragePath)
	server := localui.New(opts.Listen, runtime)
	if err := server.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "serve local UI: %v\n", err)
		return 1
	}
	return 0
}

func serveExisting(ctx context.Context, listen, storagePath string, stdout, stderr io.Writer) int {
	if err := localruntime.ValidateViewOptions(listen, storagePath); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	runtime, err := localruntime.OpenExisting(ctx, storagePath)
	if err != nil {
		fmt.Fprintf(stderr, "open audit state: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "MoniCheck persisted Local UI: http://%s/ui/static/?view=agent\nState: %s\nNo providers contacted; no analyzers rerun.\n", listen, storagePath)
	server := localui.New(listen, runtime)
	if err := server.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "serve audit UI: %v\n", err)
		return 1
	}
	return 0
}

func writeLocalProgress(output io.Writer, event execution.ProgressEvent) {
	switch event.Stage {
	case execution.ProgressStageSourceCollection:
		fmt.Fprintf(output, "Collecting evidence from %d configured source(s)...\n", event.Total)
	case execution.ProgressStageSnapshotPersistence:
		fmt.Fprintf(output, "Persisting source snapshot: %d resources, %d relationships...\n", event.ResourceCount, event.RelationshipCount)
	case execution.ProgressStageInventoryReconciliation:
		fmt.Fprintln(output, "Reconciling inventory and coverage evidence...")
	case execution.ProgressStageAnalysis:
		fmt.Fprintf(output, "Running %d analyzers...\n", event.Total)
	case execution.ProgressStageFindingPersistence:
		fmt.Fprintf(output, "Saving %d findings...\n", event.Total)
	}
}

func localDuration(value time.Duration) string {
	if value < time.Second {
		return value.Round(100 * time.Millisecond).String()
	}
	return value.Round(time.Second).String()
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "version does not accept positional arguments")
		return 2
	}
	info := buildinfo.Current()
	switch *format {
	case "text":
		fmt.Fprintf(stdout, "MoniCheck %s (%s, %s/%s)\n", info.Version, info.Commit, info.OS, info.Architecture)
		return 0
	case "json":
		encoded, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "encode build info: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(encoded))
		return 0
	default:
		fmt.Fprintf(stderr, "unsupported format %q\n", *format)
		return 2
	}
}

func runConnectors(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: monicheck connectors list | validate --config FILE")
		return 2
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return 2
		}
		fmt.Fprintln(stdout, "TYPE\tGROUP\tDESCRIPTION")
		for _, item := range localruntime.ConnectorCatalog() {
			fmt.Fprintf(stdout, "%s\t%s\t%s\n", item.Type, item.Group, item.Description)
		}
		return 0
	case "validate":
		fs := flag.NewFlagSet("connectors validate", flag.ContinueOnError)
		fs.SetOutput(stderr)
		path := fs.String("config", "", "YAML connector configuration file")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*path) == "" {
			return 2
		}
		cfg, err := localruntime.ValidateFileConfig(*path)
		if err != nil {
			fmt.Fprintf(stderr, "invalid connector config: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Connector config valid: %d connector(s)\n", len(cfg.Connectors))
		return 0
	default:
		fmt.Fprintf(stderr, "unknown connectors command %q\n", args[0])
		return 2
	}
}
func defaultStoragePath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ".monicheck-state.json"
	}
	return filepath.Join(dir, "monicheck", "local-state.json")
}
func writePrivate(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o600)
}
func usage(out io.Writer) {
	fmt.Fprintln(out, "MoniCheck - agent-native local observability audit\nUsage: monicheck local [options] | monicheck ui [options] | monicheck connectors list|validate | monicheck mcp | monicheck version")
}
