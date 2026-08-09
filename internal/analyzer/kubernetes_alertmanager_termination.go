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
	KubernetesInvalidAlertmanagerTerminationGraceAnalyzerID            = "builtin.kubernetes_invalid_alertmanager_termination_grace"
	KubernetesImmediateAlertmanagerTerminationAnalyzerID               = "builtin.kubernetes_immediate_alertmanager_termination"
	KubernetesUnsupportedAlertmanagerTerminationGraceVersionAnalyzerID = "builtin.kubernetes_unsupported_alertmanager_termination_grace_version"
)

type KubernetesAlertmanagerTerminationAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidAlertmanagerTerminationGraceAnalyzer() *KubernetesAlertmanagerTerminationAnalyzer {
	return &KubernetesAlertmanagerTerminationAnalyzer{id: KubernetesInvalidAlertmanagerTerminationGraceAnalyzerID, name: "Kubernetes Invalid Alertmanager Termination Grace"}
}
func NewKubernetesImmediateAlertmanagerTerminationAnalyzer() *KubernetesAlertmanagerTerminationAnalyzer {
	return &KubernetesAlertmanagerTerminationAnalyzer{id: KubernetesImmediateAlertmanagerTerminationAnalyzerID, name: "Kubernetes Immediate Alertmanager Termination"}
}
func NewKubernetesUnsupportedAlertmanagerTerminationGraceVersionAnalyzer() *KubernetesAlertmanagerTerminationAnalyzer {
	return &KubernetesAlertmanagerTerminationAnalyzer{id: KubernetesUnsupportedAlertmanagerTerminationGraceVersionAnalyzerID, name: "Kubernetes Unsupported Alertmanager Termination Grace Version"}
}
func (a *KubernetesAlertmanagerTerminationAnalyzer) ID() string      { return a.id }
func (a *KubernetesAlertmanagerTerminationAnalyzer) Name() string    { return a.name }
func (a *KubernetesAlertmanagerTerminationAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesAlertmanagerTerminationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesAlertmanagerTerminationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "Alertmanager" {
			continue
		}
		findingType, evidence, recommendation, matched := alertmanagerTerminationFindingContent(a.id, resource)
		if !matched {
			continue
		}
		findings = append(findings, model.Finding{ID: model.StableID(a.id, resource.ID), Type: findingType, Severity: model.SeverityCritical, Category: model.FindingCategoryReliability, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: map[string]string{"analyzer_id": a.id, "kubernetes_kind": "Alertmanager", "namespace": kubernetesResourceNamespace(resource)}, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func alertmanagerTerminationFindingContent(analyzerID string, resource model.Resource) (string, string, string, bool) {
	switch analyzerID {
	case KubernetesInvalidAlertmanagerTerminationGraceAnalyzerID:
		if resource.Metadata["alertmanager_termination_grace_declared"] != "true" || resource.Metadata["alertmanager_termination_grace_valid"] == "true" {
			return "", "", "", false
		}
		return "KubernetesInvalidAlertmanagerTerminationGrace", fmt.Sprintf("Kubernetes Alertmanager %q declares a negative or malformed terminationGracePeriodSeconds value", resource.Name), "使用非负整数配置 terminationGracePeriodSeconds；生产环境保留足够时间让 Alertmanager 完成优雅关闭。", true
	case KubernetesImmediateAlertmanagerTerminationAnalyzerID:
		if resource.Metadata["alertmanager_termination_grace_declared"] != "true" || resource.Metadata["alertmanager_termination_grace_valid"] != "true" || resource.Metadata["alertmanager_termination_grace_seconds"] != "0" {
			return "", "", "", false
		}
		return "KubernetesImmediateAlertmanagerTermination", fmt.Sprintf("Kubernetes Alertmanager %q sets terminationGracePeriodSeconds to zero, so Pods are killed without an opportunity to shut down", resource.Name), "移除零值以使用 Operator 默认值，或配置足够的正终止宽限期，避免状态损坏。", true
	case KubernetesUnsupportedAlertmanagerTerminationGraceVersionAnalyzerID:
		if resource.Metadata["alertmanager_termination_grace_version_unsupported"] != "true" {
			return "", "", "", false
		}
		return "KubernetesUnsupportedAlertmanagerTerminationGraceVersion", fmt.Sprintf("Kubernetes Alertmanager %q declares version %q with terminationGracePeriodSeconds, which requires Alertmanager 0.25 or newer", resource.Name, resource.Metadata["alertmanager_version"]), "升级 Alertmanager 到 0.25 或更高版本，或移除不受支持的字段，并确认 Operator 调谐和 Pod 启动成功。", true
	default:
		return "", "", "", false
	}
}
