package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPrometheusShortStorageRetentionAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	for _, resource := range []model.Resource{
		prometheusRetentionTestResource("short", "http://short.example", "86400"),
		prometheusRetentionTestResource("boundary", "http://boundary.example", "604800"),
		prometheusRetentionTestResource("long", "http://long.example", "2592000"),
		prometheusRetentionTestResource("extreme", "http://extreme.example", "9223372036854775807"),
		prometheusRetentionTestResource("invalid", "http://invalid.example", "not-a-number"),
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert TSDB: %v", err)
		}
	}
	unavailable := prometheusRetentionTestResource("unavailable", "http://unavailable.example", "86400")
	unavailable.Metadata[model.MetadataPrometheusRuntimeAvailable] = "false"
	if err := store.Resources.Upsert(ctx, unavailable); err != nil {
		t.Fatalf("upsert unavailable TSDB: %v", err)
	}
	other := prometheusRetentionTestResource("other", "http://other.example", "86400")
	other.Source.System = "thanos"
	if err := store.Resources.Upsert(ctx, other); err != nil {
		t.Fatalf("upsert other TSDB: %v", err)
	}

	analyzer := NewPrometheusShortStorageRetentionAnalyzer()
	findings, err := analyzer.Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute retention analyzer: %v", err)
	}
	if len(findings) != 1 ||
		findings[0].Resource.ID != "short" ||
		findings[0].Type != "PrometheusShortStorageRetention" ||
		findings[0].Severity != model.SeverityWarning ||
		findings[0].Category != model.FindingCategoryReliability ||
		findings[0].Metadata["retention"] != "24h0m0s" ||
		findings[0].Metadata["minimum_retention"] != "168h0m0s" ||
		model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability {
		t.Fatalf("unexpected retention findings: %#v", findings)
	}

	findings, err = analyzer.Execute(ctx, Context{
		Resources: store.Resources,
		Config: map[string]any{
			"prometheus_minimum_storage_retention": 48 * time.Hour,
			"allowed_prometheus_short_retentions":  []string{"http://short.example"},
		},
	})
	if err != nil {
		t.Fatalf("execute configured retention analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected URL allowlist to suppress short retention, got %#v", findings)
	}
}

func prometheusRetentionTestResource(id string, instance string, seconds string) model.Resource {
	return model.Resource{
		ID:       id,
		UID:      id,
		Type:     model.ResourceTypeTSDB,
		Name:     "prometheus TSDB",
		Source:   model.SourceInfo{System: "prometheus", Instance: instance},
		Status:   model.ResourceStatusActive,
		Metadata: map[string]string{model.MetadataPrometheusRuntimeAvailable: "true", model.MetadataPrometheusRetentionSeconds: seconds},
	}
}
