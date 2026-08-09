package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPrometheusAlertmanagerDeliveryAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		prometheusDeliveryTestResource("none", "2", "0", "0"),
		prometheusDeliveryTestResource("dropped", "2", "2", "1"),
		prometheusDeliveryTestResource("single", "2", "1", "0"),
		prometheusDeliveryTestResource("healthy", "2", "2", "0"),
		prometheusDeliveryTestResource("external-rules", "0", "0", "1"),
	}
	unavailable := prometheusDeliveryTestResource("unavailable", "2", "0", "0")
	unavailable.Metadata[model.MetadataPrometheusAMDiscoveryAvailable] = "false"
	rulesUnavailable := prometheusDeliveryTestResource("rules-unavailable", "2", "0", "0")
	rulesUnavailable.Metadata[model.MetadataRulesDiscoveryAvailable] = "false"
	deprecated := prometheusDeliveryTestResource("deprecated", "2", "0", "0")
	deprecated.Status = model.ResourceStatusDeprecated
	resources = append(resources, unavailable, rulesUnavailable, deprecated)
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert TSDB resource: %v", err)
		}
	}

	tests := []struct {
		analyzer    *PrometheusAlertmanagerDeliveryAnalyzer
		resourceID  string
		findingType string
		severity    model.Severity
	}{
		{NewPrometheusWithoutActiveAlertmanagerAnalyzer(), "none", "PrometheusWithoutActiveAlertmanager", model.SeverityCritical},
		{NewPrometheusDroppedAlertmanagerTargetsAnalyzer(), "dropped", "PrometheusDroppedAlertmanagerTargets", model.SeverityWarning},
		{NewPrometheusSingleAlertmanagerTargetAnalyzer(), "single", "PrometheusSingleAlertmanagerTarget", model.SeverityWarning},
	}
	for _, test := range tests {
		t.Run(test.analyzer.ID(), func(t *testing.T) {
			findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
			if err != nil {
				t.Fatalf("execute analyzer: %v", err)
			}
			if len(findings) != 1 ||
				findings[0].Resource.ID != test.resourceID ||
				findings[0].Type != test.findingType ||
				findings[0].Severity != test.severity ||
				findings[0].Category != model.FindingCategoryReliability ||
				model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability {
				t.Fatalf("unexpected findings: %#v", findings)
			}
		})
	}
}

func prometheusDeliveryTestResource(id string, alertingRules string, active string, dropped string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeTSDB,
		Name:   "prometheus TSDB",
		Source: model.SourceInfo{System: "prometheus", Instance: "http://" + id},
		Metadata: map[string]string{
			model.MetadataRulesDiscoveryAvailable:        "true",
			model.MetadataAlertingRuleCount:              alertingRules,
			model.MetadataPrometheusAMDiscoveryAvailable: "true",
			model.MetadataPrometheusActiveAMCount:        active,
			model.MetadataPrometheusDroppedAMCount:       dropped,
		},
		Status: model.ResourceStatusActive,
	}
}
