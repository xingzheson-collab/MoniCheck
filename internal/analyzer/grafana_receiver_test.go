package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestGrafanaReceiversUseNotificationGovernanceAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		grafanaReceiverForTest("undefined", "missing-team", map[string]string{"declared": "false", "referenced_by_route": "true"}),
		grafanaReceiverForTest("unused", "legacy-email", map[string]string{"declared": "true", model.MetadataReceiverIntegrations: "email"}),
		grafanaReceiverForTest("empty", "empty-contact", map[string]string{"declared": "true", "referenced_by_route": "true"}),
		grafanaReceiverForTest("blackhole", "blackhole", map[string]string{"declared": "true", "referenced_by_route": "true"}),
		grafanaReceiverForTest("insecure", "legacy-webhook", map[string]string{"declared": "true", model.MetadataReceiverIntegrations: "webhook", model.MetadataReceiverInsecureEndpointCount: "1"}),
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	tests := []struct {
		name        string
		analyzer    Analyzer
		findingType string
		resourceID  string
	}{
		{name: "undefined", analyzer: NewUndefinedReceiverAnalyzer(), findingType: "UndefinedReceiver", resourceID: "undefined"},
		{name: "unused", analyzer: NewUnusedReceiverAnalyzer(), findingType: "UnusedReceiver", resourceID: "unused"},
		{name: "without integration", analyzer: NewReceiverWithoutIntegrationAnalyzer(), findingType: "ReceiverWithoutIntegration", resourceID: "empty"},
		{name: "blackhole", analyzer: NewBlackholeReceiverAnalyzer(), findingType: "BlackholeReceiver", resourceID: "blackhole"},
		{name: "insecure endpoint", analyzer: NewInsecureReceiverEndpointAnalyzer(), findingType: "InsecureReceiverEndpoint", resourceID: "insecure"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
			if err != nil {
				t.Fatalf("execute analyzer: %v", err)
			}
			for _, finding := range findings {
				if finding.Type == test.findingType && finding.Resource.ID == test.resourceID {
					return
				}
			}
			t.Fatalf("expected %s finding for %s, got %#v", test.findingType, test.resourceID, findings)
		})
	}
}

func grafanaReceiverForTest(id string, name string, metadata map[string]string) model.Resource {
	metadata["receiver_name"] = name
	return model.Resource{
		ID:       id,
		Type:     model.ResourceTypeReceiver,
		Name:     name,
		Status:   model.ResourceStatusActive,
		Source:   model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "receiver:" + name},
		Metadata: metadata,
	}
}
