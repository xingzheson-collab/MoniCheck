package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusStatefulSetAnalyzers(t *testing.T) {
	store := storage.NewMemoryStore()
	rolling := prometheusStatefulSetResource("rolling", "Prometheus")
	invalid := prometheusStatefulSetResource("invalid", "Prometheus")
	invalid.Metadata["prometheus_update_strategy_invalid_setting_count"] = "1"
	ordered := prometheusStatefulSetResource("ordered", "Prometheus")
	ordered.Metadata["prometheus_pod_management_policy"] = "OrderedReady"
	onDelete := prometheusStatefulSetResource("on-delete", "PrometheusAgent")
	onDelete.Metadata["prometheus_update_strategy_type"] = "OnDelete"
	highUnavailable := prometheusStatefulSetResource("high-unavailable", "Prometheus")
	highUnavailable.Metadata["prometheus_effective_max_unavailable"] = "2"
	daemonset := prometheusStatefulSetResource("daemonset", "PrometheusAgent")
	daemonset.Metadata["prometheus_statefulset_applicable"] = "false"
	daemonset.Metadata["prometheus_update_strategy_invalid_setting_count"] = "1"
	for _, resource := range []model.Resource{rolling, invalid, ordered, onDelete, highUnavailable, daemonset} {
		if err := store.Resources.Upsert(context.Background(), resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	analysis := Context{Resources: store.Resources}
	cases := []struct {
		analyzer Analyzer
		wantID   string
	}{
		{NewKubernetesInvalidPrometheusStatefulSetStrategyAnalyzer(), invalid.ID},
		{NewKubernetesPrometheusHAOrderedPodManagementAnalyzer(), ordered.ID},
		{NewKubernetesPrometheusOnDeleteUpdateAnalyzer(), onDelete.ID},
		{NewKubernetesPrometheusHighUnavailableUpdateAnalyzer(), highUnavailable.ID},
	}
	for _, test := range cases {
		findings, err := test.analyzer.Execute(context.Background(), analysis)
		if err != nil {
			t.Fatalf("execute %s: %v", test.analyzer.ID(), err)
		}
		if len(findings) != 1 || findings[0].Resource.ID != test.wantID {
			t.Fatalf("unexpected %s findings: %#v", test.analyzer.ID(), findings)
		}
	}
}

func prometheusStatefulSetResource(name, kind string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTSDB, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": kind, "namespace": "monitoring", "prometheus_statefulset_metadata": "true", "prometheus_statefulset_applicable": "true", "prometheus_replicas": "3", "prometheus_update_strategy_invalid_setting_count": "0", "prometheus_pod_management_policy": "Parallel", "prometheus_update_strategy_type": "RollingUpdate", "prometheus_max_unavailable_valid": "true", "prometheus_effective_max_unavailable": "1"}}
}
