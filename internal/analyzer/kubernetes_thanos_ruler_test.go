package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesRuleEvaluatorCoverageAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	selected := kubernetesRuleCoverageResource("selected", "1", "1", "true")
	zeroOnly := kubernetesRuleCoverageResource("zero-only", "1", "0", "true")
	unselected := kubernetesRuleCoverageResource("unselected", "0", "0", "true")
	unknown := kubernetesRuleCoverageResource("unknown", "0", "0", "false")
	for _, resource := range []model.Resource{selected, zeroOnly, unselected, unknown} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	findings, err := NewKubernetesPrometheusRuleNotSelectedAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != unselected.ID {
		t.Fatalf("unexpected unselected findings: %#v err=%v", findings, err)
	}
	findings, err = NewKubernetesRuleEvaluatorZeroReplicaCoverageAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != zeroOnly.ID || findings[0].Severity != model.SeverityCritical {
		t.Fatalf("unexpected zero-replica findings: %#v err=%v", findings, err)
	}
}

func TestKubernetesThanosRulerDeploymentAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	paused := kubernetesThanosRulerResource("paused", "true", "1", "false")
	missingQuery := kubernetesThanosRulerResource("missing-query", "false", "0", "false")
	configured := kubernetesThanosRulerResource("configured", "false", "0", "true")
	for _, resource := range []model.Resource{paused, missingQuery, configured} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	findings, err := NewKubernetesThanosRulerPausedAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != paused.ID {
		t.Fatalf("unexpected paused findings: %#v err=%v", findings, err)
	}
	findings, err = NewKubernetesThanosRulerWithoutQueryEndpointAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != missingQuery.ID || findings[0].Severity != model.SeverityCritical {
		t.Fatalf("unexpected query findings: %#v err=%v", findings, err)
	}
}

func kubernetesRuleCoverageResource(name, selected, nonzero, evaluable string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeAlertRule, Name: name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "PrometheusRule", "namespace": "prod", "rule_evaluator_selection_candidate": "true", "rule_evaluator_selection_evaluable": evaluable, "rule_evaluator_selected_count": selected, "rule_evaluator_nonzero_selected_count": nonzero}}
}

func kubernetesThanosRulerResource(name, paused, endpointCount, queryConfig string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ThanosRuler", "namespace": "monitoring", "thanos_ruler_paused": paused, "thanos_ruler_query_endpoint_count": endpointCount, "thanos_ruler_query_config_declared": queryConfig}}
}
