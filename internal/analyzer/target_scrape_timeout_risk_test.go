package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestTargetScrapeTimeoutRiskAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	normalTarget := model.Resource{
		ID:     "target-normal",
		Type:   model.ResourceTypeTarget,
		Name:   "http://normal:9100/metrics",
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "target:normal"},
		Metadata: map[string]string{
			model.MetadataScrapeDuration: "2s",
			model.MetadataScrapeTimeout:  "10s",
		},
		Status: model.ResourceStatusActive,
	}
	riskyTarget := model.Resource{
		ID:     "target-risky",
		Type:   model.ResourceTypeTarget,
		Name:   "http://risky:9100/metrics",
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "target:risky"},
		Metadata: map[string]string{
			model.MetadataScrapeURL:      "http://risky:9100/metrics",
			model.MetadataScrapePool:     "risky-pool",
			model.MetadataScrapeDuration: "9s",
			model.MetadataScrapeTimeout:  "10s",
		},
		Status: model.ResourceStatusActive,
	}
	missingTimeoutTarget := model.Resource{
		ID:     "target-missing-timeout",
		Type:   model.ResourceTypeTarget,
		Name:   "http://missing:9100/metrics",
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "target:missing"},
		Metadata: map[string]string{
			model.MetadataScrapeDuration: "9s",
		},
		Status: model.ResourceStatusActive,
	}
	sampleTarget := model.Resource{
		ID:     "target-sample",
		Type:   model.ResourceTypeTarget,
		Name:   "sample",
		Source: model.SourceInfo{System: "sample", Instance: "local", ExternalID: "target:sample"},
		Metadata: map[string]string{
			model.MetadataScrapeDuration: "9s",
			model.MetadataScrapeTimeout:  "10s",
		},
		Status: model.ResourceStatusActive,
	}
	deprecatedRiskyTarget := model.Resource{
		ID:     "target-deprecated-risky",
		Type:   model.ResourceTypeTarget,
		Name:   "http://deprecated:9100/metrics",
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "target:deprecated"},
		Metadata: map[string]string{
			model.MetadataScrapeDuration: "9s",
			model.MetadataScrapeTimeout:  "10s",
		},
		Status: model.ResourceStatusDeprecated,
	}
	for _, resource := range []model.Resource{normalTarget, riskyTarget, missingTimeoutTarget, sampleTarget, deprecatedRiskyTarget} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	findings, err := NewTargetScrapeTimeoutRiskAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != riskyTarget.ID {
		t.Fatalf("expected risky target finding, got %s", findings[0].Resource.ID)
	}
	if findings[0].Metadata["ratio"] != "0.9000" {
		t.Fatalf("expected ratio metadata, got %#v", findings[0].Metadata)
	}
}

func TestTargetScrapeTimeoutRiskAnalyzerConfig(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	target := model.Resource{
		ID:     "target-risky",
		Type:   model.ResourceTypeTarget,
		Name:   "http://risky:9100/metrics",
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "target:risky"},
		Metadata: map[string]string{
			model.MetadataScrapeURL:      "http://risky:9100/metrics",
			model.MetadataScrapeDuration: "9s",
			model.MetadataScrapeTimeout:  "10s",
		},
		Status: model.ResourceStatusActive,
	}
	if err := store.Resources.Upsert(ctx, target); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewTargetScrapeTimeoutRiskAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config: map[string]any{
			"target_scrape_timeout_ratio_threshold": 0.95,
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no finding with higher threshold, got %d", len(findings))
	}

	findings, err = NewTargetScrapeTimeoutRiskAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config: map[string]any{
			"allowed_target_scrape_timeout_risks": "http://risky:9100/metrics",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer with allowlist: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no finding for allowed target, got %d", len(findings))
	}
}
