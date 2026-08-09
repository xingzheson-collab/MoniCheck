package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestUndefinedReceiverAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	declaredReceiver := model.Resource{
		ID:     "receiver-declared",
		Type:   model.ResourceTypeReceiver,
		Name:   "pagerduty",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "receiver:pagerduty"},
		Metadata: map[string]string{
			"declared":            "true",
			"referenced_by_route": "true",
		},
	}
	undefinedReceiver := model.Resource{
		ID:     "receiver-undefined",
		Type:   model.ResourceTypeReceiver,
		Name:   "missing-team",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "receiver:missing-team"},
		Metadata: map[string]string{
			"declared":            "false",
			"referenced_by_route": "true",
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
	deprecatedReceiver := model.Resource{
		ID:     "receiver-deprecated-undefined",
		Type:   model.ResourceTypeReceiver,
		Name:   "legacy-missing-team",
		Status: model.ResourceStatusDeprecated,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "receiver:legacy-missing-team"},
		Metadata: map[string]string{
			"declared":            "false",
			"referenced_by_route": "true",
		},
	}
	for _, resource := range []model.Resource{declaredReceiver, undefinedReceiver, runtimeReceiver, deprecatedReceiver} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewUndefinedReceiverAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "UndefinedReceiver" || findings[0].Resource.ID != undefinedReceiver.ID || findings[0].Severity != model.SeverityCritical {
		t.Fatalf("expected undefined receiver finding, got %#v", findings[0])
	}
}
