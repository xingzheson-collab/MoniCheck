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
	KubernetesInvalidThanosRulerTerminationGraceAnalyzerID = "builtin.kubernetes_invalid_thanos_ruler_termination_grace"
	KubernetesImmediateThanosRulerTerminationAnalyzerID    = "builtin.kubernetes_immediate_thanos_ruler_termination"
)

type KubernetesThanosRulerTerminationAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidThanosRulerTerminationGraceAnalyzer() *KubernetesThanosRulerTerminationAnalyzer {
	return &KubernetesThanosRulerTerminationAnalyzer{id: KubernetesInvalidThanosRulerTerminationGraceAnalyzerID, name: "Kubernetes Invalid ThanosRuler Termination Grace"}
}
func NewKubernetesImmediateThanosRulerTerminationAnalyzer() *KubernetesThanosRulerTerminationAnalyzer {
	return &KubernetesThanosRulerTerminationAnalyzer{id: KubernetesImmediateThanosRulerTerminationAnalyzerID, name: "Kubernetes Immediate ThanosRuler Termination"}
}

func (a *KubernetesThanosRulerTerminationAnalyzer) ID() string      { return a.id }
func (a *KubernetesThanosRulerTerminationAnalyzer) Name() string    { return a.name }
func (a *KubernetesThanosRulerTerminationAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerTerminationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesThanosRulerTerminationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" {
			continue
		}
		findingType, evidence, recommendation, category, matched := thanosRulerTerminationFindingContent(a.id, resource)
		if !matched {
			continue
		}
		findings = append(findings, model.Finding{ID: model.StableID(a.id, resource.ID), Type: findingType, Severity: model.SeverityCritical, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: map[string]string{"analyzer_id": a.id, "kubernetes_kind": "ThanosRuler", "namespace": kubernetesResourceNamespace(resource)}, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func thanosRulerTerminationFindingContent(analyzerID string, resource model.Resource) (string, string, string, model.FindingCategory, bool) {
	switch analyzerID {
	case KubernetesInvalidThanosRulerTerminationGraceAnalyzerID:
		if resource.Metadata["thanos_ruler_termination_grace_declared"] != "true" || resource.Metadata["thanos_ruler_termination_grace_valid"] == "true" {
			return "", "", "", "", false
		}
		return "KubernetesInvalidThanosRulerTerminationGrace", fmt.Sprintf("Kubernetes ThanosRuler %q declares a negative or malformed terminationGracePeriodSeconds value", resource.Name), "使用非负整数配置 terminationGracePeriodSeconds，并保留足够时间完成规则状态和远端写入关闭。", model.FindingCategoryConfiguration, true
	case KubernetesImmediateThanosRulerTerminationAnalyzerID:
		if resource.Metadata["thanos_ruler_termination_grace_declared"] != "true" || resource.Metadata["thanos_ruler_termination_grace_valid"] != "true" || resource.Metadata["thanos_ruler_termination_grace_seconds"] != "0" {
			return "", "", "", "", false
		}
		return "KubernetesImmediateThanosRulerTermination", fmt.Sprintf("Kubernetes ThanosRuler %q sets terminationGracePeriodSeconds to zero, so Pods are killed without an opportunity to shut down", resource.Name), "移除零值以使用 120 秒 Operator 默认值，或配置足够的正终止宽限期，降低规则状态损坏和未发送样本风险。", model.FindingCategoryReliability, true
	default:
		return "", "", "", "", false
	}
}
