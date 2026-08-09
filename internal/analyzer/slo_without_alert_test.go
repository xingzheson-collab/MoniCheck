package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestSLOWithoutAlertAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		sloTestRule("api-fast", model.ResourceTypeRecordingRule, "api-availability", "99.9", false),
		sloTestRule("api-slow", model.ResourceTypeRecordingRule, "api-availability", "99.9", false),
		sloTestRule("worker-recording", model.ResourceTypeRecordingRule, "worker-latency", "99.5", false),
		sloTestRule("worker-alert", model.ResourceTypeAlertRule, "worker-latency", "99.5", false),
		sloTestRule("db-recording", model.ResourceTypeRecordingRule, "db-availability", "99.95", false),
		sloTestRule("db-disabled-alert", model.ResourceTypeAlertRule, "db-availability", "99.95", true),
		{ID: "unnamed-slo", Type: model.ResourceTypeRecordingRule, Name: "slo:sli_error:ratio_rate5m", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataSLORule: "true"}},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewSLOWithoutAlertAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected API and DB SLO findings, got %#v", findings)
	}
	bySLO := make(map[string]model.Finding)
	for _, finding := range findings {
		bySLO[finding.Metadata["slo_name"]] = finding
	}
	if bySLO["api-availability"].Metadata["recording_rule_count"] != "2" || bySLO["api-availability"].Metadata["slo_objectives"] != "99.9" {
		t.Fatalf("expected grouped API recording rules, got %#v", bySLO["api-availability"])
	}
	if bySLO["db-availability"].ID == "" || bySLO["worker-latency"].ID != "" {
		t.Fatalf("expected disabled alert not to cover DB and active alert to cover worker, got %#v", bySLO)
	}

	findings, err = NewSLOWithoutAlertAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config:    map[string]any{"allowed_slos_without_alert": "api-availability,db-availability"},
	})
	if err != nil || len(findings) != 0 {
		t.Fatalf("expected allowlisted SLOs to be skipped, findings=%#v err=%v", findings, err)
	}
}

func sloTestRule(id string, resourceType model.ResourceType, sloName string, objective string, disabled bool) model.Resource {
	metadata := map[string]string{
		model.MetadataSLORule:      "true",
		model.MetadataSLOName:      sloName,
		model.MetadataSLOObjective: objective,
	}
	if disabled {
		metadata[model.MetadataDisabled] = "true"
	}
	return model.Resource{
		ID: id, Type: resourceType, Name: id, Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus", Instance: "prod"}, Metadata: metadata,
	}
}
