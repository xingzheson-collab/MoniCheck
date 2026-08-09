package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestTempoServiceDiscoveryTruncatedAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	truncated := model.Resource{
		ID: "tempo-service-tag", Type: model.ResourceTypeTraceTag, Name: "resource.service.name",
		Source: model.SourceInfo{System: "tempo", Instance: "http://tempo:3200"},
		Metadata: map[string]string{
			model.MetadataValueDiscoveryAvailable:        "true",
			model.MetadataTraceServiceDiscoveryTruncated: "true",
			model.MetadataTraceServiceCount:              "200",
			model.MetadataTraceServiceLimit:              "200",
			model.MetadataTraceLookback:                  "24h0m0s",
		},
		Status: model.ResourceStatusActive,
	}
	complete := truncated
	complete.ID = "tempo-complete-tag"
	complete.Name = "service.name"
	complete.Metadata = map[string]string{
		model.MetadataValueDiscoveryAvailable: "true",
		model.MetadataTraceServiceCount:       "20",
		model.MetadataTraceServiceLimit:       "200",
		model.MetadataTraceLookback:           "24h0m0s",
	}
	for _, resource := range []model.Resource{truncated, complete} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewTempoServiceDiscoveryTruncatedAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != truncated.ID {
		t.Fatalf("expected one truncated service discovery finding, got %#v", findings)
	}
	if model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability ||
		findings[0].Metadata["limit"] != "200" ||
		findings[0].Metadata["lookback"] != "24h0m0s" {
		t.Fatalf("unexpected finding metadata: %#v", findings[0])
	}
}
