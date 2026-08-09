package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestDuplicateObservabilityQueryAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	primaryLogPanel := model.Resource{
		ID:     "panel-log-primary",
		Type:   model.ResourceTypePanel,
		Name:   "API Errors",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataQuery:         `sum(count_over_time({app="api"} |= "error" [5m]))`,
			model.MetadataQueryLanguage: "logql",
		},
	}
	duplicateLogPanel := model.Resource{
		ID:     "panel-log-duplicate",
		Type:   model.ResourceTypePanel,
		Name:   "API Error Copy",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataQuery:         `sum( count_over_time( {app="api"} |= "error" [5m] ) )`,
			model.MetadataQueryLanguage: "logql",
		},
	}
	tracePanel := model.Resource{
		ID:     "panel-trace",
		Type:   model.ResourceTypePanel,
		Name:   "Trace",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataQuery:         `sum(count_over_time({app="api"} |= "error" [5m]))`,
			model.MetadataQueryLanguage: "traceql",
		},
	}
	promPanel := model.Resource{
		ID:     "panel-prom",
		Type:   model.ResourceTypePanel,
		Name:   "Prometheus",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: `sum(rate(http_requests_total[5m]))`,
		},
	}
	inactiveLogPanel := model.Resource{
		ID:     "panel-log-inactive",
		Type:   model.ResourceTypePanel,
		Name:   "Inactive",
		Status: model.ResourceStatusDeprecated,
		Metadata: map[string]string{
			model.MetadataQuery:         `sum(count_over_time({app="api"} |= "error" [5m]))`,
			model.MetadataQueryLanguage: "logql",
		},
	}
	for _, resource := range []model.Resource{primaryLogPanel, duplicateLogPanel, tracePanel, promPanel, inactiveLogPanel} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewDuplicateObservabilityQueryAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "DuplicateObservabilityQuery" {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
	if findings[0].Resource.ID != duplicateLogPanel.ID && findings[0].Resource.ID != primaryLogPanel.ID {
		t.Fatalf("expected duplicate log panel finding, got %#v", findings[0].Resource)
	}
	if findings[0].Metadata["query_language"] != "logql" || findings[0].Metadata["duplicate_count"] != "2" {
		t.Fatalf("expected duplicate metadata, got %#v", findings[0].Metadata)
	}
}
