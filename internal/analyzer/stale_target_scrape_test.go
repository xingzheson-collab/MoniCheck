package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestStaleTargetScrapeAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	freshTarget := model.Resource{
		ID:     "target-fresh",
		Type:   model.ResourceTypeTarget,
		Name:   "http://fresh:9100/metrics",
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "target:fresh"},
		Metadata: map[string]string{
			model.MetadataLastScrape: now.Add(-time.Minute).Format(time.RFC3339),
		},
		Status: model.ResourceStatusActive,
	}
	staleTarget := model.Resource{
		ID:     "target-stale",
		Type:   model.ResourceTypeTarget,
		Name:   "http://stale:9100/metrics",
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "target:stale"},
		Metadata: map[string]string{
			model.MetadataScrapeURL:  "http://stale:9100/metrics",
			model.MetadataScrapePool: "stale-pool",
			model.MetadataLastScrape: now.Add(-time.Hour).Format(time.RFC3339),
		},
		Status: model.ResourceStatusActive,
	}
	unknownTarget := model.Resource{
		ID:     "target-unknown",
		Type:   model.ResourceTypeTarget,
		Name:   "http://unknown:9100/metrics",
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "target:unknown"},
		Metadata: map[string]string{
			model.MetadataLastScrape: "not-a-time",
		},
		Status: model.ResourceStatusActive,
	}
	sampleTarget := model.Resource{
		ID:     "target-sample",
		Type:   model.ResourceTypeTarget,
		Name:   "sample",
		Source: model.SourceInfo{System: "sample", Instance: "local", ExternalID: "target:sample"},
		Metadata: map[string]string{
			model.MetadataLastScrape: now.Add(-time.Hour).Format(time.RFC3339),
		},
		Status: model.ResourceStatusActive,
	}
	deprecatedStaleTarget := model.Resource{
		ID:     "target-deprecated-stale",
		Type:   model.ResourceTypeTarget,
		Name:   "http://deprecated:9100/metrics",
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "target:deprecated"},
		Metadata: map[string]string{
			model.MetadataLastScrape: now.Add(-time.Hour).Format(time.RFC3339),
		},
		Status: model.ResourceStatusDeprecated,
	}
	for _, resource := range []model.Resource{freshTarget, staleTarget, unknownTarget, sampleTarget, deprecatedStaleTarget} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	findings, err := NewStaleTargetScrapeAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != staleTarget.ID {
		t.Fatalf("expected stale target finding, got %s", findings[0].Resource.ID)
	}
	if findings[0].Metadata["last_scrape"] == "" || findings[0].Metadata["age"] == "" {
		t.Fatalf("expected stale scrape metadata, got %#v", findings[0].Metadata)
	}
}

func TestStaleTargetScrapeAnalyzerConfig(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	target := model.Resource{
		ID:     "target-stale",
		Type:   model.ResourceTypeTarget,
		Name:   "http://stale:9100/metrics",
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "target:stale"},
		Metadata: map[string]string{
			model.MetadataScrapeURL:  "http://stale:9100/metrics",
			model.MetadataLastScrape: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
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

	findings, err := NewStaleTargetScrapeAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config: map[string]any{
			"stale_target_scrape_threshold": "2h",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no finding with higher threshold, got %d", len(findings))
	}

	findings, err = NewStaleTargetScrapeAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config: map[string]any{
			"allowed_stale_target_scrapes": "http://stale:9100/metrics",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer with allowlist: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no finding for allowed target, got %d", len(findings))
	}
}
