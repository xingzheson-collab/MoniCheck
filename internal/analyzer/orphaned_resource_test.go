package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOrphanedResourceAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		{
			ID: "orphan-metric", Type: model.ResourceTypeMetric, Name: "removed_metric", Status: model.ResourceStatusOrphan,
			Source: model.SourceInfo{System: "prometheus", Instance: "http://prometheus.test"},
			Metadata: map[string]string{
				model.MetadataConnectorID:         "prometheus",
				model.MetadataConnectorLastSeenAt: "2026-07-18T01:00:00Z",
				model.MetadataConnectorOrphanedAt: "2026-07-18T02:00:00Z",
			},
		},
		{ID: "orphan-target", Type: model.ResourceTypeTarget, Name: "removed-target", Status: model.ResourceStatusOrphan, Source: model.SourceInfo{System: "prometheus", Instance: "http://prometheus.test"}},
		{ID: "active-dashboard", Type: model.ResourceTypeDashboard, Name: "active", Status: model.ResourceStatusActive},
		{ID: "derived-service", Type: model.ResourceTypeService, Name: "payments", Status: model.ResourceStatusOrphan, Source: model.SourceInfo{System: "monicheck"}, Metadata: map[string]string{"derived": "true"}},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewOrphanedResourceAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected two concrete orphan findings, got %#v", findings)
	}
	byResource := map[string]model.Finding{}
	for _, finding := range findings {
		byResource[finding.Resource.ID] = finding
	}
	metricFinding := byResource["orphan-metric"]
	if metricFinding.Type != "OrphanedResource" || metricFinding.Category != model.FindingCategoryLifecycle || metricFinding.Severity != model.SeverityWarning {
		t.Fatalf("unexpected metric finding: %#v", metricFinding)
	}
	if metricFinding.Metadata["connector_id"] != "prometheus" || metricFinding.Metadata["last_seen_at"] == "" || metricFinding.Metadata["orphaned_at"] == "" {
		t.Fatalf("expected connector lifecycle evidence, got %#v", metricFinding.Metadata)
	}
	if byResource["orphan-target"].Metadata["connector_id"] != "prometheus" {
		t.Fatalf("expected source system fallback for legacy orphan, got %#v", byResource["orphan-target"])
	}
}
