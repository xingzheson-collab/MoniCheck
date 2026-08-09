package connector

import (
	"testing"
	"time"

	"monicheck/internal/model"
)

func TestAnnotateSLORuleMetadata(t *testing.T) {
	tests := []struct {
		name      string
		resource  model.Resource
		expected  bool
		sloName   string
		objective string
	}{
		{
			name: "sloth labels",
			resource: model.Resource{Type: model.ResourceTypeRecordingRule, Labels: map[string]string{
				"sloth_slo": "api-availability", "sloth_objective": "99.9", "sloth_window": "5m",
			}},
			expected: true, sloName: "api-availability", objective: "99.9",
		},
		{
			name:     "burn rate alert",
			resource: model.Resource{Type: model.ResourceTypeAlertRule, Name: "APIErrorBudgetBurnRate"},
			expected: true,
		},
		{
			name: "slo recording output",
			resource: model.Resource{Type: model.ResourceTypeRecordingRule, Metadata: map[string]string{
				model.MetadataRecordingRuleOutput: "slo:sli_error:ratio_rate5m",
			}},
			expected: true,
		},
		{
			name:     "ordinary alert",
			resource: model.Resource{Type: model.ResourceTypeAlertRule, Name: "APIHighLatency"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			annotateSLORuleMetadata(&test.resource)
			if got := test.resource.Metadata[model.MetadataSLORule] == "true"; got != test.expected {
				t.Fatalf("expected slo=%t, got metadata %#v", test.expected, test.resource.Metadata)
			}
			if test.resource.Metadata[model.MetadataSLOName] != test.sloName || test.resource.Metadata[model.MetadataSLOObjective] != test.objective {
				t.Fatalf("unexpected normalized SLO metadata: %#v", test.resource.Metadata)
			}
			if test.name == "sloth labels" && test.resource.Metadata[model.MetadataSLOWindow] != "5m" {
				t.Fatalf("expected normalized SLO window metadata, got %#v", test.resource.Metadata)
			}
		})
	}
}

func TestConnectorRuleMappersAnnotateSLO(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	prometheusConnector := &PrometheusConnector{baseURL: "http://prometheus.example", system: prometheusSystem}
	prometheusRule, ok := prometheusConnector.ruleResource(prometheusRuleGroup{Name: "api-slo"}, prometheusRule{
		Type: "recording", Name: "slo:sli_error:ratio_rate5m", Labels: map[string]string{"sloth_slo": "api-availability", "sloth_objective": "99.9", "sloth_window": "5m"},
	}, now)
	if !ok || prometheusRule.Metadata[model.MetadataSLORule] != "true" || prometheusRule.Metadata[model.MetadataSLOName] != "api-availability" || prometheusRule.Metadata[model.MetadataSLOWindow] != "5m" {
		t.Fatalf("expected Prometheus SLO metadata, got %#v", prometheusRule.Metadata)
	}

	n9eRule, ok := n9eRuleResource(map[string]any{
		"id": "slo-1", "name": "APIErrorBudgetBurnRate", "labels": map[string]any{"slo": "api-availability", "objective": "99.95"},
	}, "http://n9e.example", now)
	if !ok || n9eRule.Metadata[model.MetadataSLORule] != "true" || n9eRule.Metadata[model.MetadataSLOObjective] != "99.95" {
		t.Fatalf("expected N9E SLO metadata, got %#v", n9eRule.Metadata)
	}

	grafanaRule := grafanaAlertRuleResource(grafanaAlertRule{
		UID: "slo-1", Title: "APIErrorBudgetBurnRate", Labels: map[string]string{"slo": "api-availability", "objective": "99.9"},
	}, nil, "http://grafana.example", now)
	if grafanaRule.Metadata[model.MetadataSLORule] != "true" || grafanaRule.Metadata[model.MetadataSLOName] != "api-availability" {
		t.Fatalf("expected Grafana SLO metadata, got %#v", grafanaRule.Metadata)
	}
}
