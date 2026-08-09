package report

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestBuildLocalRegressionComparesLatestTwoAutomaticSnapshots(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	exports := []model.ReportExport{
		localSnapshotExport("first", now.Add(-3*time.Hour), `{"open_finding_count":20,"critical_count":4,"coverage_missing_signals":5,"coverage_unknown_signals":3,"coverage_percent":60,"coverage_evidence_completeness_percent":50}`),
		localSnapshotExport("previous", now.Add(-2*time.Hour), `{"open_finding_count":8,"critical_count":1,"coverage_missing_signals":2,"coverage_unknown_signals":1,"coverage_percent":80,"coverage_evidence_completeness_percent":75}`),
		localSnapshotExport("current", now.Add(-time.Hour), `{"open_finding_count":10,"critical_count":2,"coverage_missing_signals":3,"coverage_unknown_signals":0,"coverage_percent":75,"coverage_evidence_completeness_percent":100}`),
		trendExport("manual", "governance", now, `{"open_finding_count":99,"critical_count":99,"coverage_percent":1}`),
	}
	for _, export := range exports {
		if err := store.ReportExports.Save(ctx, export); err != nil {
			t.Fatalf("save export: %v", err)
		}
	}

	got, err := BuildLocalRegression(ctx, store)
	if err != nil {
		t.Fatalf("build local regression: %v", err)
	}
	if got.State != "MIXED" || got.SnapshotCount != 3 {
		t.Fatalf("unexpected regression state: %#v", got)
	}
	if got.Previous == nil || got.Previous.ReportID != "previous" || got.Current == nil || got.Current.ReportID != "current" {
		t.Fatalf("expected latest-two comparison, got previous=%#v current=%#v", got.Previous, got.Current)
	}
	if got.Delta["open_finding_count"] != 2 || got.Delta["coverage_percent"] != -5 || got.Delta["coverage_unknown_signals"] != -1 {
		t.Fatalf("unexpected metric delta: %#v", got.Delta)
	}
	if len(got.RegressedMetrics) != 4 || len(got.ImprovedMetrics) != 2 || got.ImprovedMetrics[0] != "coverage_unknown_signals" || got.ImprovedMetrics[1] != "coverage_evidence_completeness_percent" {
		t.Fatalf("unexpected classification: regressed=%#v improved=%#v", got.RegressedMetrics, got.ImprovedMetrics)
	}
}

func TestSaveLocalPostureSnapshotIsExecutionIdempotent(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	execution := model.ExecutionResult{ID: "execution-1", FinishedAt: time.Now().UTC()}
	if err := store.Findings.ReplaceOpenByAnalyzer(ctx, "test.analyzer", []model.Finding{{ID: "finding-1", Type: "MissingOwner", Severity: model.SeverityWarning, Status: model.FindingStatusOpen, Metadata: map[string]string{"analyzer_id": "test.analyzer"}}}); err != nil {
		t.Fatal(err)
	}
	manual, err := BuildExport(ctx, store, "governance", "json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(manual.Content, localFindingIndexKey) {
		t.Fatal("manual Governance export must not contain the private automatic Finding index")
	}

	first, err := SaveLocalPostureSnapshot(ctx, store, execution)
	if err != nil {
		t.Fatalf("save first snapshot: %v", err)
	}
	second, err := SaveLocalPostureSnapshot(ctx, store, execution)
	if err != nil {
		t.Fatalf("save duplicate snapshot: %v", err)
	}
	exports, err := store.ReportExports.List(ctx)
	if err != nil {
		t.Fatalf("list snapshots: %v", err)
	}
	if first.ID != second.ID || len(exports) != 1 || first.Origin != LocalPostureSnapshotOrigin || first.ExecutionID != execution.ID {
		t.Fatalf("snapshot is not execution-idempotent: first=%#v second=%#v exports=%d", first, second, len(exports))
	}
	index := readLocalFindingIndex(first.Content)
	if index == nil || !index.Complete || index.Count != 1 || len(index.Items) != 1 || index.Items[0].ID != "finding-1" {
		t.Fatalf("automatic snapshot must contain a complete private Finding index: %#v", index)
	}
	regression, err := BuildLocalRegression(ctx, store)
	if err != nil || regression.State != "BASELINE" || regression.SnapshotCount != 1 {
		t.Fatalf("expected one baseline snapshot, got %#v err=%v", regression, err)
	}
}

func TestBuildLocalRegressionDetectsFindingReplacementWithStableTotals(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	previous := indexedLocalSnapshotExport(t, "previous", now.Add(-time.Hour), []LocalFindingIndexItem{
		{ID: "persistent", Type: "MissingOwner", Severity: model.SeverityWarning, Status: model.FindingStatusOpen},
		{ID: "cleared", Type: "UnusedMetric", Severity: model.SeverityWarning, Status: model.FindingStatusOpen},
		{ID: "reopen", Type: "MissingRunbook", Severity: model.SeverityWarning, Status: model.FindingStatusAcked},
	})
	current := indexedLocalSnapshotExport(t, "current", now, []LocalFindingIndexItem{
		{ID: "persistent", Type: "MissingOwner", Severity: model.SeverityWarning, Status: model.FindingStatusOpen},
		{ID: "private-finding-identity", Type: "HighCardinalityMetric", Severity: model.SeverityWarning, Status: model.FindingStatusOpen},
		{ID: "reopen", Type: "MissingRunbook", Severity: model.SeverityWarning, Status: model.FindingStatusOpen},
	})
	for _, export := range []model.ReportExport{previous, current} {
		if err := store.ReportExports.Save(ctx, export); err != nil {
			t.Fatal(err)
		}
	}
	got, err := BuildLocalRegression(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "MIXED" || got.FindingDiff == nil || !got.FindingDiff.Comparable || got.FindingDiff.NewOpen != 1 || got.FindingDiff.Reopened != 1 || got.FindingDiff.Cleared != 1 || got.FindingDiff.PersistentOpen != 1 {
		t.Fatalf("expected identity churn to be visible despite stable totals: %#v", got)
	}
	if got.Delta["open_finding_count"] != 0 || !containsString(got.RegressedMetrics, "new_open_findings") || !containsString(got.ImprovedMetrics, "left_open_findings") {
		t.Fatalf("expected Finding movement classification: %#v", got)
	}
	encoded, err := json.Marshal(got.FindingDiff)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "private-finding-identity") {
		t.Fatalf("Finding movement projection must not expose private Finding IDs: %s", encoded)
	}
}

func TestBuildLocalRegressionSkipsFindingDiffAcrossIndexUpgrade(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	legacy := localSnapshotExport("legacy", now.Add(-time.Hour), `{"open_finding_count":1,"critical_count":0,"coverage_missing_signals":0,"coverage_unknown_signals":0,"coverage_percent":100}`)
	current := indexedLocalSnapshotExport(t, "current", now, []LocalFindingIndexItem{{ID: "new", Type: "MissingOwner", Severity: model.SeverityWarning, Status: model.FindingStatusOpen}})
	for _, export := range []model.ReportExport{legacy, current} {
		if err := store.ReportExports.Save(ctx, export); err != nil {
			t.Fatal(err)
		}
	}
	got, err := BuildLocalRegression(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	if got.FindingDiff == nil || got.FindingDiff.Comparable || got.FindingDiff.Reason != "FINDING_INDEX_UNAVAILABLE" || containsString(got.RegressedMetrics, "new_open_findings") {
		t.Fatalf("legacy snapshots must not create synthetic Finding movement: %#v", got)
	}
}

func TestBuildLocalRegressionDoesNotCompareEvidenceCompletenessAcrossContractUpgrade(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	for _, export := range []model.ReportExport{
		localSnapshotExport("legacy", now.Add(-time.Hour), `{"open_finding_count":1,"critical_count":0,"coverage_missing_signals":0,"coverage_unknown_signals":1,"coverage_percent":100}`),
		localSnapshotExport("current", now, `{"open_finding_count":1,"critical_count":0,"coverage_missing_signals":0,"coverage_unknown_signals":1,"coverage_percent":100,"coverage_evidence_completeness_percent":33}`),
	} {
		if err := store.ReportExports.Save(ctx, export); err != nil {
			t.Fatal(err)
		}
	}
	got, err := BuildLocalRegression(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	for _, metric := range append(got.RegressedMetrics, got.ImprovedMetrics...) {
		if metric == "coverage_evidence_completeness_percent" {
			t.Fatalf("contract-upgrade metric must not be compared without two values: %#v", got)
		}
	}
}

func localSnapshotExport(id string, createdAt time.Time, content string) model.ReportExport {
	export := trendExport(id, "governance", createdAt, content)
	export.Origin = LocalPostureSnapshotOrigin
	export.ExecutionID = "execution-" + id
	return export
}

func indexedLocalSnapshotExport(t *testing.T, id string, createdAt time.Time, items []LocalFindingIndexItem) model.ReportExport {
	t.Helper()
	payload := map[string]any{
		"open_finding_count":       2,
		"critical_count":           0,
		"coverage_missing_signals": 0,
		"coverage_unknown_signals": 0,
		"coverage_percent":         100,
		localFindingIndexKey:       localFindingIndex{Complete: true, Count: len(items), Items: items},
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return localSnapshotExport(id, createdAt, string(encoded))
}

func containsString(items []string, expected string) bool {
	for _, item := range items {
		if item == expected {
			return true
		}
	}
	return false
}
