package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestUnusedReceiverAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	usedReceiver := model.Resource{
		ID:     "receiver-used",
		Type:   model.ResourceTypeReceiver,
		Name:   "pagerduty",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "receiver:pagerduty"},
		Metadata: map[string]string{
			"declared":            "true",
			"referenced_by_route": "true",
		},
	}
	unusedReceiver := model.Resource{
		ID:     "receiver-unused",
		Type:   model.ResourceTypeReceiver,
		Name:   "legacy-email",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "receiver:legacy-email"},
		Metadata: map[string]string{
			"declared": "true",
		},
	}
	runtimeReceiver := model.Resource{
		ID:     "receiver-runtime",
		Type:   model.ResourceTypeReceiver,
		Name:   "runtime-only",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "receiver:runtime-only"},
		Metadata: map[string]string{
			"seen_in_alerts": "true",
		},
	}
	otherSystemReceiver := model.Resource{
		ID:     "receiver-other",
		Type:   model.ResourceTypeReceiver,
		Name:   "other",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "other", Instance: "local", ExternalID: "receiver:other"},
		Metadata: map[string]string{
			"declared": "true",
		},
	}
	deprecatedReceiver := model.Resource{
		ID:     "receiver-deprecated-unused",
		Type:   model.ResourceTypeReceiver,
		Name:   "legacy-unused",
		Status: model.ResourceStatusDeprecated,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "receiver:legacy-unused"},
		Metadata: map[string]string{
			"declared": "true",
		},
	}
	for _, resource := range []model.Resource{usedReceiver, unusedReceiver, runtimeReceiver, otherSystemReceiver, deprecatedReceiver} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewUnusedReceiverAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "UnusedReceiver" || findings[0].Resource.ID != unusedReceiver.ID || findings[0].Severity != model.SeverityWarning {
		t.Fatalf("expected unused receiver finding, got %#v", findings[0])
	}
}
