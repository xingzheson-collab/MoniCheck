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
	KubernetesAlertmanagerConfigNotSelectedAnalyzerID         = "builtin.kubernetes_alertmanager_config_not_selected"
	KubernetesAlertmanagerConfigZeroReplicaCoverageAnalyzerID = "builtin.kubernetes_alertmanager_config_zero_replica_coverage"
	KubernetesAlertmanagerPausedAnalyzerID                    = "builtin.kubernetes_alertmanager_paused"
)

type KubernetesAlertmanagerConfigNotSelectedAnalyzer struct{}
type KubernetesAlertmanagerConfigZeroReplicaCoverageAnalyzer struct{}
type KubernetesAlertmanagerPausedAnalyzer struct{}

func NewKubernetesAlertmanagerConfigNotSelectedAnalyzer() *KubernetesAlertmanagerConfigNotSelectedAnalyzer {
	return &KubernetesAlertmanagerConfigNotSelectedAnalyzer{}
}
func NewKubernetesAlertmanagerConfigZeroReplicaCoverageAnalyzer() *KubernetesAlertmanagerConfigZeroReplicaCoverageAnalyzer {
	return &KubernetesAlertmanagerConfigZeroReplicaCoverageAnalyzer{}
}
func NewKubernetesAlertmanagerPausedAnalyzer() *KubernetesAlertmanagerPausedAnalyzer {
	return &KubernetesAlertmanagerPausedAnalyzer{}
}

func (a *KubernetesAlertmanagerConfigNotSelectedAnalyzer) ID() string {
	return KubernetesAlertmanagerConfigNotSelectedAnalyzerID
}
func (a *KubernetesAlertmanagerConfigNotSelectedAnalyzer) Name() string {
	return "Kubernetes AlertmanagerConfig Not Selected"
}
func (a *KubernetesAlertmanagerConfigNotSelectedAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesAlertmanagerConfigNotSelectedAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeNotificationPolicy}
}
func (a *KubernetesAlertmanagerConfigNotSelectedAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesAlertmanagerConfigCoverageFindings(ctx, analysis, a.ID(), false)
}

func (a *KubernetesAlertmanagerConfigZeroReplicaCoverageAnalyzer) ID() string {
	return KubernetesAlertmanagerConfigZeroReplicaCoverageAnalyzerID
}
func (a *KubernetesAlertmanagerConfigZeroReplicaCoverageAnalyzer) Name() string {
	return "Kubernetes AlertmanagerConfig Covered Only By Zero-Replica Alertmanager"
}
func (a *KubernetesAlertmanagerConfigZeroReplicaCoverageAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesAlertmanagerConfigZeroReplicaCoverageAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeNotificationPolicy}
}
func (a *KubernetesAlertmanagerConfigZeroReplicaCoverageAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesAlertmanagerConfigCoverageFindings(ctx, analysis, a.ID(), true)
}

func kubernetesAlertmanagerConfigCoverageFindings(ctx context.Context, analysis Context, analyzerID string, zeroReplica bool) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeNotificationPolicy})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "AlertmanagerConfig" || resource.Metadata["alertmanager_selection_candidate"] != "true" {
			continue
		}
		selected := strings.TrimSpace(resource.Metadata["alertmanager_selected_count"])
		nonzero := strings.TrimSpace(resource.Metadata["alertmanager_nonzero_selected_count"])
		if zeroReplica {
			if selected == "0" || nonzero != "0" {
				continue
			}
		} else if resource.Metadata["alertmanager_selection_evaluable"] != "true" || selected != "0" {
			continue
		}
		namespace := kubernetesResourceNamespace(resource)
		findingType := "KubernetesAlertmanagerConfigNotSelected"
		severity := model.SeverityWarning
		category := model.FindingCategoryConfiguration
		evidence := fmt.Sprintf("Kubernetes AlertmanagerConfig %q in namespace %q is not selected by any imported Alertmanager", resource.Name, namespace)
		recommendation := "检查 Alertmanager 的 alertmanagerConfigSelector、alertmanagerConfigNamespaceSelector、alertmanagerConfiguration 以及 AlertmanagerConfig 和 Namespace 标签。"
		if zeroReplica {
			findingType = "KubernetesAlertmanagerConfigZeroReplicaCoverage"
			severity = model.SeverityCritical
			category = model.FindingCategoryReliability
			evidence = fmt.Sprintf("Kubernetes AlertmanagerConfig %q in namespace %q is selected only by Alertmanager resources with zero desired replicas", resource.Name, namespace)
			recommendation = "将至少一个选择该配置的 Alertmanager replicas 调整为非零值，或让其他可部署的 Alertmanager 选择它。"
		}
		findings = append(findings, model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "AlertmanagerConfig", "namespace": namespace, "alertmanager_selected_count": selected, "alertmanager_nonzero_selected_count": nonzero}, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func (a *KubernetesAlertmanagerPausedAnalyzer) ID() string {
	return KubernetesAlertmanagerPausedAnalyzerID
}
func (a *KubernetesAlertmanagerPausedAnalyzer) Name() string {
	return "Kubernetes Alertmanager Reconciliation Paused"
}
func (a *KubernetesAlertmanagerPausedAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesAlertmanagerPausedAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}
func (a *KubernetesAlertmanagerPausedAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "Alertmanager" || resource.Metadata["alertmanager_paused"] != "true" {
			continue
		}
		namespace := kubernetesResourceNamespace(resource)
		findings = append(findings, model.Finding{ID: model.StableID(a.ID(), resource.ID), Type: "KubernetesAlertmanagerPaused", Severity: model.SeverityWarning, Category: model.FindingCategoryConfiguration, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{fmt.Sprintf("Kubernetes Alertmanager %q in namespace %q has spec.paused=true", resource.Name, namespace)}, Recommendation: "确认调谐暂停仍是有意维护状态；完成后恢复 spec.paused=false，并验证 StatefulSet、生成配置和集群成员状态。", Metadata: map[string]string{"analyzer_id": a.ID(), "kubernetes_kind": "Alertmanager", "namespace": namespace}, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}
