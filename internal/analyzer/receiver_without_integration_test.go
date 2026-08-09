package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestReceiverWithoutIntegrationAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	withIntegration := model.Resource{
		ID:     "receiver-with-integration",
		Type:   model.ResourceTypeReceiver,
		Name:   "pagerduty",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "receiver:pagerduty"},
		Metadata: map[string]string{
			"declared":                         "true",
			model.MetadataReceiverIntegrations: "pagerduty",
		},
	}
	withoutIntegration := model.Resource{
		ID:     "receiver-without-integration",
		Type:   model.ResourceTypeReceiver,
		Name:   "platform",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "receiver:platform"},
		Metadata: map[string]string{
			"declared": "true",
		},
	}
	blackholeReceiver := model.Resource{
		ID:     "receiver-blackhole",
		Type:   model.ResourceTypeReceiver,
		Name:   "blackhole",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "receiver:blackhole"},
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
	deprecatedReceiver := model.Resource{
		ID:     "receiver-deprecated-without-integration",
		Type:   model.ResourceTypeReceiver,
		Name:   "legacy-platform",
		Status: model.ResourceStatusDeprecated,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "receiver:legacy-platform"},
		Metadata: map[string]string{
			"declared": "true",
		},
	}
	for _, resource := range []model.Resource{withIntegration, withoutIntegration, blackholeReceiver, runtimeReceiver, deprecatedReceiver} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewReceiverWithoutIntegrationAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "ReceiverWithoutIntegration" || findings[0].Resource.ID != withoutIntegration.ID || findings[0].Severity != model.SeverityCritical {
		t.Fatalf("expected receiver without integration finding, got %#v", findings[0])
	}
}
