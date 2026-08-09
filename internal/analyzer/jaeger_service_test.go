package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestJaegerOperationDiscoveryTruncatedAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	truncated := model.Resource{
		ID: "jaeger-checkout", Type: model.ResourceTypeService, Name: "checkout",
		Source: model.SourceInfo{System: "jaeger"},
		Metadata: map[string]string{
			model.MetadataOperationDiscoveryAvailable: "true",
			model.MetadataOperationDiscoveryTruncated: "true",
			model.MetadataOperationCount:              "1250",
			model.MetadataOperationLimit:              "1000",
		},
		Status: model.ResourceStatusActive,
	}
	complete := truncated
	complete.ID = "jaeger-payments"
	complete.Name = "payments"
	complete.Metadata = map[string]string{
		model.MetadataOperationDiscoveryAvailable: "true",
		model.MetadataOperationCount:              "20",
		model.MetadataOperationLimit:              "1000",
	}
	unavailable := truncated
	unavailable.ID = "jaeger-inventory"
	unavailable.Name = "inventory"
	unavailable.Metadata = map[string]string{
		model.MetadataOperationDiscoveryAvailable: "false",
		model.MetadataOperationDiscoveryTruncated: "true",
	}
	for _, resource := range []model.Resource{truncated, complete, unavailable} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert service: %v", err)
		}
	}
	findings, err := NewJaegerOperationDiscoveryTruncatedAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != truncated.ID ||
		findings[0].Metadata["count"] != "1250" || findings[0].Metadata["limit"] != "1000" ||
		model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryConfiguration {
		t.Fatalf("expected one Jaeger truncation finding, got %#v", findings)
	}
}

func TestJaegerDependencyDiscoveryTruncatedAnalyzerGroupsByInstance(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	truncated := model.Resource{
		ID: "jaeger-api", Type: model.ResourceTypeService, Name: "api",
		Source: model.SourceInfo{System: "jaeger", Instance: "http://jaeger-a:16686"},
		Metadata: map[string]string{
			model.MetadataAPMTopologyDiscoveryAvailable: "true",
			model.MetadataAPMTopologyDiscoveryTruncated: "true",
			model.MetadataAPMTopologyDependencyCount:    "8000",
			model.MetadataAPMTopologyDependencyLimit:    "5000",
			model.MetadataAPMLookback:                   "24h0m0s",
		},
		Status: model.ResourceStatusActive,
	}
	sameInstance := truncated
	sameInstance.ID = "jaeger-billing"
	sameInstance.Name = "billing"
	complete := truncated
	complete.ID = "jaeger-complete"
	complete.Name = "complete"
	complete.Source.Instance = "http://jaeger-b:16686"
	complete.Metadata = map[string]string{
		model.MetadataAPMTopologyDiscoveryAvailable: "true",
		model.MetadataAPMTopologyDependencyCount:    "20",
		model.MetadataAPMTopologyDependencyLimit:    "5000",
	}
	for _, resource := range []model.Resource{sameInstance, truncated, complete} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert service: %v", err)
		}
	}
	findings, err := NewJaegerDependencyDiscoveryTruncatedAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != truncated.ID ||
		findings[0].Metadata["count"] != "8000" ||
		findings[0].Metadata["limit"] != "5000" ||
		findings[0].Metadata["lookback"] != "24h0m0s" ||
		findings[0].Category != model.FindingCategoryReliability {
		t.Fatalf("expected one grouped Jaeger dependency truncation finding, got %#v", findings)
	}
}
