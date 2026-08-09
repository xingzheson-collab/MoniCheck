package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesScrapeConfigEmptyStaticAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	clean := kubernetesScrapeConfigResource("clean", "clean", "2", "0", "0", "1")
	partial := kubernetesScrapeConfigResource("partial", "partial", "2", "0", "1", "2")
	discoveryOnly := kubernetesScrapeConfigResource("discovery", "discovery", "0", "1", "0", "0")
	for _, resource := range []model.Resource{clean, partial, discoveryOnly} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewKubernetesScrapeConfigEmptyStaticAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != partial.ID {
		t.Fatalf("expected partial static config finding, got %#v", findings)
	}
	if findings[0].Severity != model.SeverityWarning || findings[0].Metadata["scrape_config_empty_static_count"] != "1" {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}
