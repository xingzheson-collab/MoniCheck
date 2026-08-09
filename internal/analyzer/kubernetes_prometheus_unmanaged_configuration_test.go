package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusUnmanagedConfigurationAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	unmanaged := kubernetesPrometheusResource("unmanaged", "false")
	unmanaged.Metadata["prometheus_configuration_managed"] = "false"
	unmanaged.Metadata["prometheus_additional_scrape_configs_declared"] = "true"
	managed := kubernetesPrometheusResource("managed", "false")
	managed.Metadata["prometheus_configuration_managed"] = "true"
	agent := kubernetesPrometheusAgentResource("unmanaged-agent", "1")
	agent.Metadata["prometheus_configuration_managed"] = "false"
	nonKubernetes := model.Resource{ID: "runtime", UID: "runtime", Type: model.ResourceTypeTSDB, Name: "runtime", Source: model.SourceInfo{System: "prometheus"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"prometheus_configuration_managed": "false"}}
	for _, resource := range []model.Resource{unmanaged, managed, agent, nonKubernetes} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewKubernetesPrometheusUnmanagedConfigurationAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected Prometheus and Agent findings, got %#v", findings)
	}
	if findings[0].Category != model.FindingCategoryConfiguration || findings[0].Severity != model.SeverityWarning {
		t.Fatalf("unexpected finding classification: %#v", findings[0])
	}
}
