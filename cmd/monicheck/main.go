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

	"monicheck/internal/buildinfo"
	"monicheck/internal/localruntime"
	"monicheck/internal/localui"
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

func runLocal(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("local", flag.ContinueOnError)
	fs.SetOutput(stderr)
	opts := localruntime.Options{}
	check := false
	format, reportOut := "text", ""
	fs.StringVar(&opts.Listen, "listen", "127.0.0.1:8080", "loopback address for the Local UI")
	fs.StringVar(&opts.StoragePath, "storage-path", defaultStoragePath(), "durable local state file")
	fs.StringVar(&opts.LogLevel, "log-level", "quiet", "quiet, debug, info, warn, or error")
	fs.StringVar(&opts.PrometheusURL, "prometheus-url", os.Getenv("MONICHECK_PROMETHEUS_URL"), "Prometheus endpoint")
	fs.StringVar(&opts.GrafanaURL, "grafana-url", os.Getenv("MONICHECK_GRAFANA_URL"), "Grafana endpoint")
	fs.StringVar(&opts.AlertmanagerURL, "alertmanager-url", os.Getenv("MONICHECK_ALERTMANAGER_URL"), "Alertmanager endpoint")
	fs.StringVar(&opts.KubernetesManifest, "kubernetes-manifest", os.Getenv("MONICHECK_KUBERNETES_MANIFEST_PATH"), "manifest file or directory")
	fs.BoolVar(&check, "check", false, "scan once and exit")
	fs.StringVar(&format, "format", "text", "check output: text or json")
	fs.StringVar(&reportOut, "report-out", "", "write governance JSON to a private file")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	if err := localruntime.ValidateOptions(opts); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	runtime, err := localruntime.New(ctx, opts)
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
	if check {
		passed := len(regression.RegressedMetrics) == 0
		result := map[string]any{"passed": passed, "state": regression.State, "snapshot_count": regression.SnapshotCount, "regressed_metrics": regression.RegressedMetrics}
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
	fmt.Fprintf(stdout, "MoniCheck Local UI: http://%s/ui/static/\nState: %s\n", opts.Listen, opts.StoragePath)
	server := localui.New(opts.Listen, runtime)
	if err := server.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "serve local UI: %v\n", err)
		return 1
	}
	return 0
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "version accepts no arguments")
		return 2
	}
	info := buildinfo.Current()
	fmt.Fprintf(stdout, "MoniCheck %s (%s, %s/%s)\n", info.Version, info.Commit, info.OS, info.Architecture)
	return 0
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
	fmt.Fprintln(out, "MoniCheck - local observability governance\nUsage: monicheck local [options] | monicheck version")
}
