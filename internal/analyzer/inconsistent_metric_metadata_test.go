package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestInconsistentMetricMetadataAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	for _, resource := range []model.Resource{
		{
			ID:     "metric-type-conflict",
			Type:   model.ResourceTypeMetric,
			Name:   "request_duration",
			Status: model.ResourceStatusActive,
			Metadata: map[string]string{
				model.MetadataMetricTypeVariants: `["gauge","histogram"]`,
				model.MetadataMetricHelpVariants: `["Request duration","Duration of requests"]`,
			},
		},
		{
			ID:     "metric-help-conflict",
			Type:   model.ResourceTypeMetric,
			Name:   "queue_depth",
			Status: model.ResourceStatusActive,
			Metadata: map[string]string{
				model.MetadataMetricHelpVariants: `["Queue depth","Pending work"]`,
			},
		},
		{
			ID:     "metric-consistent",
			Type:   model.ResourceTypeMetric,
			Name:   "workers_total",
			Status: model.ResourceStatusActive,
		},
		{
			ID:     "metric-deprecated-conflict",
			Type:   model.ResourceTypeMetric,
			Name:   "legacy_total",
			Status: model.ResourceStatusDeprecated,
			Metadata: map[string]string{
				model.MetadataMetricTypeVariants: `["counter","gauge"]`,
			},
		},
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewInconsistentMetricMetadataAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 active metadata conflict findings, got %#v", findings)
	}
	severityByResource := make(map[string]model.Severity)
	for _, finding := range findings {
		severityByResource[finding.Resource.ID] = finding.Severity
	}
	if severityByResource["metric-type-conflict"] != model.SeverityCritical {
		t.Fatalf("expected TYPE conflict to be critical, got %#v", findings)
	}
	if severityByResource["metric-help-conflict"] != model.SeverityWarning {
		t.Fatalf("expected HELP-only conflict to be warning, got %#v", findings)
	}
}
