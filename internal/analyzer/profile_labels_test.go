package analyzer

import (
	"context"
	"fmt"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestProfileLabelGovernanceAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	for _, label := range []model.Resource{
		{
			ID:     "profile-label-request",
			Type:   model.ResourceTypeProfileLabel,
			Name:   "request_id",
			Status: model.ResourceStatusActive,
			Metadata: map[string]string{
				model.MetadataProfileLabel:           "request_id",
				model.MetadataProfileLabelValueCount: "250",
			},
		},
		{
			ID:     "profile-label-env",
			Type:   model.ResourceTypeProfileLabel,
			Name:   "environment",
			Status: model.ResourceStatusActive,
			Metadata: map[string]string{
				model.MetadataProfileLabel:           "environment",
				model.MetadataProfileLabelValueCount: "2",
			},
		},
	} {
		if err := store.Resources.Upsert(ctx, label); err != nil {
			t.Fatalf("upsert label: %v", err)
		}
	}
	for index := 0; index < 3; index++ {
		if err := store.Resources.Upsert(ctx, model.Resource{
			ID:     fmt.Sprintf("profile-value-%d", index),
			Type:   model.ResourceTypeProfileLabelValue,
			Name:   "request_id=<redacted>",
			Status: model.ResourceStatusActive,
			Metadata: map[string]string{
				model.MetadataProfileLabel:     "request_id",
				model.MetadataValueFingerprint: fmt.Sprintf("fingerprint-%d", index),
				model.MetadataValueRedacted:    "true",
			},
		}); err != nil {
			t.Fatalf("upsert value: %v", err)
		}
	}

	cardinalityFindings, err := NewHighCardinalityProfileLabelAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config:    map[string]any{"profile_label_value_threshold": 100},
	})
	if err != nil || len(cardinalityFindings) != 1 {
		t.Fatalf("expected one cardinality finding, findings=%#v err=%v", cardinalityFindings, err)
	}
	if cardinalityFindings[0].Resource.ID != "profile-label-request" ||
		cardinalityFindings[0].Metadata["value_count"] != "250" ||
		cardinalityFindings[0].Type != "HighCardinalityProfileLabel" {
		t.Fatalf("unexpected cardinality finding: %#v", cardinalityFindings[0])
	}

	riskyFindings, err := NewRiskyProfileLabelAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config:    map[string]any{"risky_profile_label_names": []string{"request-id"}},
	})
	if err != nil || len(riskyFindings) != 1 {
		t.Fatalf("expected one risky-label finding, findings=%#v err=%v", riskyFindings, err)
	}
	if riskyFindings[0].Resource.ID != "profile-label-request" || riskyFindings[0].Type != "RiskyProfileLabel" {
		t.Fatalf("unexpected risky-label finding: %#v", riskyFindings[0])
	}
}

func TestProfileServiceIsAnObservabilitySignal(t *testing.T) {
	resource := model.Resource{
		ID:     "profile-service-checkout",
		Type:   model.ResourceTypeProfileService,
		Name:   "checkout",
		Status: model.ResourceStatusActive,
	}
	if signal := observabilitySignal(resource); signal != "profiles" {
		t.Fatalf("expected profiles observability signal, got %q", signal)
	}
	if !isServiceMemberResource(resource.Type) {
		t.Fatal("expected ProfileService to participate in service graph analysis")
	}
}
