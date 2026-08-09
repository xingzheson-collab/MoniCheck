package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestSLOWindowCoverageAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		sloWindowTestRule("healthy-short", "healthy", "5m"),
		sloWindowTestRule("healthy-long", "healthy", "6h"),
		sloWindowTestRule("invalid-good", "invalid", "5m"),
		sloWindowTestRule("invalid-bad", "invalid", "soon"),
		sloWindowTestRule("single", "single", "30m"),
		sloWindowTestRule("short-a", "short-only", "5m"),
		sloWindowTestRule("short-b", "short-only", "30m"),
		sloTestRule("unobserved", model.ResourceTypeRecordingRule, "unobserved", "99.9", false),
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewSLOWindowCoverageAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected invalid, insufficient, and incomplete window findings, got %#v", findings)
	}
	bySLO := make(map[string]model.Finding)
	for _, finding := range findings {
		bySLO[finding.Metadata["slo_name"]] = finding
	}
	if bySLO["invalid"].Type != "InvalidSLOWindow" || bySLO["invalid"].Severity != model.SeverityCritical {
		t.Fatalf("unexpected invalid window finding: %#v", bySLO["invalid"])
	}
	if bySLO["single"].Type != "InsufficientSLOWindows" {
		t.Fatalf("unexpected insufficient window finding: %#v", bySLO["single"])
	}
	if bySLO["short-only"].Type != "IncompleteSLOWindowCoverage" || bySLO["short-only"].Metadata["short_window_count"] != "2" || bySLO["short-only"].Metadata["long_window_count"] != "0" {
		t.Fatalf("unexpected incomplete window finding: %#v", bySLO["short-only"])
	}
	if bySLO["healthy"].ID != "" || bySLO["unobserved"].ID != "" {
		t.Fatalf("healthy and window-unobserved SLOs should be skipped: %#v", bySLO)
	}

	findings, err = NewSLOWindowCoverageAnalyzer().Execute(ctx, Context{Resources: store.Resources, Config: map[string]any{"allowed_slo_window_issues": "invalid,single,short-only"}})
	if err != nil || len(findings) != 0 {
		t.Fatalf("expected allowlisted window issues to be skipped, findings=%#v err=%v", findings, err)
	}
}

func sloWindowTestRule(id string, sloName string, window string) model.Resource {
	resource := sloTestRule(id, model.ResourceTypeRecordingRule, sloName, "99.9", false)
	resource.Metadata[model.MetadataSLOWindow] = window
	return resource
}
