package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestSLOObjectiveQualityAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		sloTestRule("healthy-a", model.ResourceTypeRecordingRule, "healthy", "99.9", false),
		sloTestRule("healthy-b", model.ResourceTypeAlertRule, "healthy", "0.999", false),
		sloTestRule("missing", model.ResourceTypeRecordingRule, "missing", "", false),
		sloTestRule("invalid-a", model.ResourceTypeRecordingRule, "invalid", "100%", false),
		sloTestRule("invalid-b", model.ResourceTypeAlertRule, "invalid", "99.9", false),
		sloTestRule("conflict-a", model.ResourceTypeRecordingRule, "conflict", "99.9", false),
		sloTestRule("conflict-b", model.ResourceTypeAlertRule, "conflict", "99.5%", false),
		sloTestRule("disabled-conflict", model.ResourceTypeAlertRule, "healthy", "80", true),
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewSLOObjectiveQualityAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected missing, invalid, and inconsistent objective findings, got %#v", findings)
	}
	bySLO := make(map[string]model.Finding)
	for _, finding := range findings {
		bySLO[finding.Metadata["slo_name"]] = finding
	}
	if bySLO["missing"].Type != "MissingSLOObjective" || bySLO["missing"].Severity != model.SeverityWarning {
		t.Fatalf("unexpected missing objective finding: %#v", bySLO["missing"])
	}
	if bySLO["invalid"].Type != "InvalidSLOObjective" || bySLO["invalid"].Severity != model.SeverityCritical {
		t.Fatalf("unexpected invalid objective finding: %#v", bySLO["invalid"])
	}
	if bySLO["conflict"].Type != "InconsistentSLOObjective" || bySLO["conflict"].Metadata["normalized_objective_values"] != "0.995,0.999" {
		t.Fatalf("unexpected inconsistent objective finding: %#v", bySLO["conflict"])
	}
	if bySLO["healthy"].ID != "" {
		t.Fatalf("equivalent percent and ratio objectives should be healthy: %#v", bySLO["healthy"])
	}

	findings, err = NewSLOObjectiveQualityAnalyzer().Execute(ctx, Context{Resources: store.Resources, Config: map[string]any{"allowed_slo_objective_issues": "missing,invalid,conflict"}})
	if err != nil || len(findings) != 0 {
		t.Fatalf("expected allowlisted objective issues to be skipped, findings=%#v err=%v", findings, err)
	}
}
