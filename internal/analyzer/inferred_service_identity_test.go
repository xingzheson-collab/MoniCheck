package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestInferredServiceIdentityAnalyzerOnlyReportsActiveInferredServices(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	services := []model.Resource{
		{ID: "inferred", Type: model.ResourceTypeService, Name: "checkout", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataServiceIdentitySource: "prometheus.job", model.MetadataServiceIdentityConfidence: "INFERRED"}},
		{ID: "declared", Type: model.ResourceTypeService, Name: "orders", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataServiceIdentitySource: "label.service", model.MetadataServiceIdentityConfidence: "DECLARED"}},
		{ID: "orphan", Type: model.ResourceTypeService, Name: "legacy", Status: model.ResourceStatusOrphan, Metadata: map[string]string{model.MetadataServiceIdentityConfidence: "INFERRED"}},
	}
	for _, service := range services {
		if err := store.Resources.Upsert(ctx, service); err != nil {
			t.Fatal(err)
		}
	}
	findings, err := NewInferredServiceIdentityAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != "inferred" || findings[0].Type != "InferredServiceIdentity" || findings[0].Metadata["service_identity_source"] != "prometheus.job" {
		t.Fatalf("unexpected inferred identity findings: %#v", findings)
	}
	assertEnglishRecommendation(t, findings[0])
}
