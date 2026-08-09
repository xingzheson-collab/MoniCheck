package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	KubernetesPrometheusRuleNotSelectedAnalyzerID        = "builtin.kubernetes_prometheus_rule_not_selected"
	KubernetesRuleEvaluatorZeroReplicaCoverageAnalyzerID = "builtin.kubernetes_rule_evaluator_zero_replica_coverage"
)

type KubernetesPrometheusRuleNotSelectedAnalyzer struct{}
type KubernetesRuleEvaluatorZeroReplicaCoverageAnalyzer struct{}

func NewKubernetesPrometheusRuleNotSelectedAnalyzer() *KubernetesPrometheusRuleNotSelectedAnalyzer {
	return &KubernetesPrometheusRuleNotSelectedAnalyzer{}
}
func NewKubernetesRuleEvaluatorZeroReplicaCoverageAnalyzer() *KubernetesRuleEvaluatorZeroReplicaCoverageAnalyzer {
	return &KubernetesRuleEvaluatorZeroReplicaCoverageAnalyzer{}
}

func (a *KubernetesPrometheusRuleNotSelectedAnalyzer) ID() string {
	return KubernetesPrometheusRuleNotSelectedAnalyzerID
}
func (a *KubernetesPrometheusRuleNotSelectedAnalyzer) Name() string {
	return "Kubernetes PrometheusRule Not Selected"
}
func (a *KubernetesPrometheusRuleNotSelectedAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusRuleNotSelectedAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule}
}

func (a *KubernetesPrometheusRuleNotSelectedAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesRuleEvaluatorCoverageFindings(ctx, analysis, a.ID(), false)
}

func (a *KubernetesRuleEvaluatorZeroReplicaCoverageAnalyzer) ID() string {
	return KubernetesRuleEvaluatorZeroReplicaCoverageAnalyzerID
}
func (a *KubernetesRuleEvaluatorZeroReplicaCoverageAnalyzer) Name() string {
	return "Kubernetes Rule Covered Only By Zero-Replica Evaluators"
}
func (a *KubernetesRuleEvaluatorZeroReplicaCoverageAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesRuleEvaluatorZeroReplicaCoverageAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule}
}

func (a *KubernetesRuleEvaluatorZeroReplicaCoverageAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesRuleEvaluatorCoverageFindings(ctx, analysis, a.ID(), true)
}

func kubernetesRuleEvaluatorCoverageFindings(ctx context.Context, analysis Context, analyzerID string, zeroReplica bool) ([]model.Finding, error) {
	resources := make([]model.Resource, 0)
	for _, resourceType := range []model.ResourceType{model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule} {
		items, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: resourceType})
		if err != nil {
			return nil, err
		}
		resources = append(resources, items...)
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "PrometheusRule" || resource.Metadata["rule_evaluator_selection_candidate"] != "true" {
			continue
		}
		selected := strings.TrimSpace(resource.Metadata["rule_evaluator_selected_count"])
		nonzero := strings.TrimSpace(resource.Metadata["rule_evaluator_nonzero_selected_count"])
		if zeroReplica {
			if selected == "0" || nonzero != "0" {
				continue
			}
		} else if resource.Metadata["rule_evaluator_selection_evaluable"] != "true" || selected != "0" {
			continue
		}
		namespace := kubernetesResourceNamespace(resource)
		findingType := "KubernetesPrometheusRuleNotSelected"
		severity := model.SeverityWarning
		category := model.FindingCategoryConfiguration
		evidence := fmt.Sprintf("Kubernetes PrometheusRule entry %q in namespace %q is not selected by any imported Prometheus or ThanosRuler", resource.Name, namespace)
		recommendation := "检查 Prometheus/ThanosRuler 的 ruleSelector、ruleNamespaceSelector 以及 PrometheusRule 和 Namespace 标签，确保该规则由至少一个执行器选中。"
		if zeroReplica {
			findingType = "KubernetesRuleEvaluatorZeroReplicaCoverage"
			severity = model.SeverityCritical
			category = model.FindingCategoryReliability
			evidence = fmt.Sprintf("Kubernetes PrometheusRule entry %q in namespace %q is selected only by rule evaluators with zero desired replicas", resource.Name, namespace)
			recommendation = "将至少一个选择该规则的 Prometheus 或 ThanosRuler replicas 调整为非零值，或让其他可部署的规则执行器选择它。"
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category,
			Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation,
			Metadata: map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "PrometheusRule", "namespace": namespace, "rule_evaluator_selected_count": selected, "rule_evaluator_nonzero_selected_count": nonzero},
			Status:   model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}
