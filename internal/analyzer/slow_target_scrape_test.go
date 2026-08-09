package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestSlowTargetScrapeAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	normalTarget := model.Resource{
		ID:     "target-normal",
		Type:   model.ResourceTypeTarget,
		Name:   "http://api:9100/metrics",
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "target:api"},
		Metadata: map[string]string{
			model.MetadataScrapeDuration: "500ms",
		},
		Status: model.ResourceStatusActive,
	}
	slowTarget := model.Resource{
		ID:     "target-slow",
		Type:   model.ResourceTypeTarget,
		Name:   "http://slow:9100/metrics",
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "target:slow"},
		Metadata: map[string]string{
			model.MetadataScrapeURL:      "http://slow:9100/metrics",
			model.MetadataScrapePool:     "slow-pool",
			model.MetadataScrapeDuration: "8s",
		},
		Status: model.ResourceStatusActive,
	}
	unknownTarget := model.Resource{
		ID:     "target-unknown",
		Type:   model.ResourceTypeTarget,
		Name:   "http://unknown:9100/metrics",
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "target:unknown"},
		Metadata: map[string]string{
			model.MetadataScrapeDuration: "not-a-duration",
		},
		Status: model.ResourceStatusActive,
	}
	sampleTarget := model.Resource{
		ID:     "target-sample",
		Type:   model.ResourceTypeTarget,
		Name:   "sample",
		Source: model.SourceInfo{System: "sample", Instance: "local", ExternalID: "target:sample"},
		Metadata: map[string]string{
			model.MetadataScrapeDuration: "8s",
		},
		Status: model.ResourceStatusActive,
	}
	deprecatedSlowTarget := model.Resource{
		ID:     "target-deprecated-slow",
		Type:   model.ResourceTypeTarget,
		Name:   "http://deprecated:9100/metrics",
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "target:deprecated"},
		Metadata: map[string]string{
			model.MetadataScrapeDuration: "10s",
		},
		Status: model.ResourceStatusDeprecated,
	}
	for _, resource := range []model.Resource{normalTarget, slowTarget, unknownTarget, sampleTarget, deprecatedSlowTarget} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	findings, err := NewSlowTargetScrapeAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != slowTarget.ID {
		t.Fatalf("expected slow target finding, got %s", findings[0].Resource.ID)
	}
	if findings[0].Metadata["scrape_duration"] != "8s" {
		t.Fatalf("expected scrape duration metadata, got %#v", findings[0].Metadata)
	}
}

func TestSlowTargetScrapeAnalyzerConfig(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	target := model.Resource{
		ID:     "target-slow",
		Type:   model.ResourceTypeTarget,
		Name:   "http://slow:9100/metrics",
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "target:slow"},
		Metadata: map[string]string{
			model.MetadataScrapeURL:      "http://slow:9100/metrics",
			model.MetadataScrapeDuration: "8s",
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

	findings, err := NewSlowTargetScrapeAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config: map[string]any{
			"slow_target_scrape_threshold": "10s",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no finding with higher threshold, got %d", len(findings))
	}

	findings, err = NewSlowTargetScrapeAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config: map[string]any{
			"allowed_slow_target_scrapes": "http://slow:9100/metrics",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer with allowlist: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no finding for allowed target, got %d", len(findings))
	}
}
