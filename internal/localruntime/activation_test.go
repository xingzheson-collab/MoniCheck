package localruntime

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"monicheck/internal/buildinfo"
	"monicheck/internal/model"
	"monicheck/internal/report"
)

func TestActivationReceiptIsBoundedAndPrivacySafe(t *testing.T) {
	summary := governanceEvidenceSummary{
		ResourceCount: 10, FindingCount: 4, CoverageServiceCount: 2, CoveragePercent: 75,
		CoverageMissingSignals: 1, CoverageUnknownSignals: 2, CoverageEvaluableSignals: 4,
		CoverageEvidenceState: "PARTIAL", CoverageEvidenceCompletenessPercent: 67,
	}
	summary.Coverage.InferredServiceCount = 1
	summary.Cost.CurrentSeries = 24000
	timing := report.LocalActivationTiming{ElapsedMilliseconds: 42000, TargetSeconds: 900, WithinTarget: true}
	receipt := buildActivationReceipt(summary, []model.ConnectorStatus{{Status: model.ExecutionStatusSucceeded}}, timing, true, time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC), buildinfo.Info{Version: "v0.6.2", Commit: strings.Repeat("a", 40), OS: "linux", Architecture: "arm64"})
	if !receipt.Ready || receipt.Outcome != "READY" || receipt.TimeToFirstReportSeconds == nil || *receipt.TimeToFirstReportSeconds != 42 || receipt.WithinTarget == nil || !*receipt.WithinTarget {
		t.Fatalf("unexpected activation result: %#v", receipt)
	}
	if receipt.Counts.Sources != 1 || receipt.Counts.InferredServices != 1 || receipt.Counts.CurrentSeries != 24000 || receipt.Coverage.EvidenceState != "PARTIAL" {
		t.Fatalf("aggregate evidence was not retained: %#v", receipt)
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, privateValue := range []string{"prometheus.internal", "checkout", "bearer-token", "dashboard query", "wusong"} {
		if strings.Contains(string(body), privateValue) {
			t.Fatalf("receipt leaked %q: %s", privateValue, body)
		}
	}
	for _, excluded := range []string{"credentials", "endpoints", "finding_evidence", "machine_identity", "resource_names", "user_identity"} {
		if !strings.Contains(string(body), excluded) {
			t.Fatalf("receipt did not disclose excluded class %q: %s", excluded, body)
		}
	}
}

func TestPrometheusDatasourceUIDRequiresBothShortcutSources(t *testing.T) {
	base := Options{Listen: "127.0.0.1:8080", StoragePath: "state.json", PrometheusURL: "https://prometheus.test", PrometheusDatasourceUID: "prom-main"}
	if err := ValidateOptions(base); err == nil || !strings.Contains(err.Error(), "requires both") {
		t.Fatalf("expected missing Grafana validation, got %v", err)
	}
	base.GrafanaURL = "https://grafana.test"
	if err := ValidateOptions(base); err != nil {
		t.Fatalf("valid datasource binding rejected: %v", err)
	}
}

func TestActivationReceiptBlocksWithoutConnectedInventory(t *testing.T) {
	receipt := buildActivationReceipt(governanceEvidenceSummary{}, []model.ConnectorStatus{{Status: model.ExecutionStatusFailed}}, report.LocalActivationTiming{}, false, time.Now(), buildinfo.Info{})
	if receipt.Ready || receipt.Outcome != "BLOCKED" || receipt.TimeToFirstReportSeconds != nil || receipt.Stages[0].State != "BLOCKED" {
		t.Fatalf("unexpected blocked receipt: %#v", receipt)
	}
}
