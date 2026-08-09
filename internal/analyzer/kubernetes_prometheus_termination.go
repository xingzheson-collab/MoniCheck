package analyzer

import (
	"context"
	"fmt"
	"sort"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	KubernetesInvalidPrometheusTerminationGraceAnalyzerID = "builtin.kubernetes_invalid_prometheus_termination_grace"
	KubernetesImmediatePrometheusTerminationAnalyzerID    = "builtin.kubernetes_immediate_prometheus_termination"
)

type KubernetesPrometheusTerminationAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidPrometheusTerminationGraceAnalyzer() *KubernetesPrometheusTerminationAnalyzer {
	return &KubernetesPrometheusTerminationAnalyzer{id: KubernetesInvalidPrometheusTerminationGraceAnalyzerID, name: "Kubernetes Invalid Prometheus Termination Grace"}
}

func NewKubernetesImmediatePrometheusTerminationAnalyzer() *KubernetesPrometheusTerminationAnalyzer {
	return &KubernetesPrometheusTerminationAnalyzer{id: KubernetesImmediatePrometheusTerminationAnalyzerID, name: "Kubernetes Immediate Prometheus Termination"}
}

func (a *KubernetesPrometheusTerminationAnalyzer) ID() string      { return a.id }
func (a *KubernetesPrometheusTerminationAnalyzer) Name() string    { return a.name }
func (a *KubernetesPrometheusTerminationAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusTerminationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *KubernetesPrometheusTerminationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := resource.Metadata["kubernetes_kind"]
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "Prometheus" && kind != "PrometheusAgent") {
			continue
		}
		findingType, evidence, recommendation, category, matched := prometheusTerminationFindingContent(a.id, resource)
		if !matched {
			continue
		}
		findings = append(findings, model.Finding{ID: model.StableID(a.id, resource.ID), Type: findingType, Severity: model.SeverityCritical, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: map[string]string{"analyzer_id": a.id, "kubernetes_kind": kind, "namespace": kubernetesResourceNamespace(resource)}, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func prometheusTerminationFindingContent(analyzerID string, resource model.Resource) (string, string, string, model.FindingCategory, bool) {
	kind := resource.Metadata["kubernetes_kind"]
	switch analyzerID {
	case KubernetesInvalidPrometheusTerminationGraceAnalyzerID:
		if resource.Metadata["prometheus_termination_grace_declared"] != "true" || resource.Metadata["prometheus_termination_grace_valid"] == "true" {
			return "", "", "", "", false
		}
		return "KubernetesInvalidPrometheusTerminationGrace", fmt.Sprintf("Kubernetes %s %q declares a negative or malformed terminationGracePeriodSeconds value", kind, resource.Name), "使用非负整数配置 terminationGracePeriodSeconds，并保留足够时间完成 WAL/TSDB flush 和远端写入关闭。", model.FindingCategoryConfiguration, true
	case KubernetesImmediatePrometheusTerminationAnalyzerID:
		if resource.Metadata["prometheus_termination_grace_declared"] != "true" || resource.Metadata["prometheus_termination_grace_valid"] != "true" || resource.Metadata["prometheus_termination_grace_seconds"] != "0" {
			return "", "", "", "", false
		}
		return "KubernetesImmediatePrometheusTermination", fmt.Sprintf("Kubernetes %s %q sets terminationGracePeriodSeconds to zero, so Pods are killed without an opportunity to shut down", kind, resource.Name), "移除零值以使用 Operator 默认宽限期，或配置足够的正终止宽限期，降低 WAL/TSDB 状态损坏和未发送样本风险。", model.FindingCategoryReliability, true
	default:
		return "", "", "", "", false
	}
}
