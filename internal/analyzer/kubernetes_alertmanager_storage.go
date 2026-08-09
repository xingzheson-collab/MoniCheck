package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	KubernetesEphemeralAlertmanagerStorageAnalyzerID   = "builtin.kubernetes_ephemeral_alertmanager_storage"
	KubernetesConflictingAlertmanagerStorageAnalyzerID = "builtin.kubernetes_conflicting_alertmanager_storage"
	KubernetesInvalidAlertmanagerRetentionAnalyzerID   = "builtin.kubernetes_invalid_alertmanager_retention"
)

type KubernetesEphemeralAlertmanagerStorageAnalyzer struct{}
type KubernetesConflictingAlertmanagerStorageAnalyzer struct{}
type KubernetesInvalidAlertmanagerRetentionAnalyzer struct{}

func NewKubernetesEphemeralAlertmanagerStorageAnalyzer() *KubernetesEphemeralAlertmanagerStorageAnalyzer {
	return &KubernetesEphemeralAlertmanagerStorageAnalyzer{}
}

func NewKubernetesConflictingAlertmanagerStorageAnalyzer() *KubernetesConflictingAlertmanagerStorageAnalyzer {
	return &KubernetesConflictingAlertmanagerStorageAnalyzer{}
}

func NewKubernetesInvalidAlertmanagerRetentionAnalyzer() *KubernetesInvalidAlertmanagerRetentionAnalyzer {
	return &KubernetesInvalidAlertmanagerRetentionAnalyzer{}
}

func (a *KubernetesEphemeralAlertmanagerStorageAnalyzer) ID() string {
	return KubernetesEphemeralAlertmanagerStorageAnalyzerID
}
func (a *KubernetesEphemeralAlertmanagerStorageAnalyzer) Name() string {
	return "Kubernetes Ephemeral Alertmanager Storage"
}
func (a *KubernetesEphemeralAlertmanagerStorageAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesEphemeralAlertmanagerStorageAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}
func (a *KubernetesEphemeralAlertmanagerStorageAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesAlertmanagerStorageFindings(ctx, analysis, a.ID())
}

func (a *KubernetesConflictingAlertmanagerStorageAnalyzer) ID() string {
	return KubernetesConflictingAlertmanagerStorageAnalyzerID
}
func (a *KubernetesConflictingAlertmanagerStorageAnalyzer) Name() string {
	return "Kubernetes Conflicting Alertmanager Storage"
}
func (a *KubernetesConflictingAlertmanagerStorageAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesConflictingAlertmanagerStorageAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}
func (a *KubernetesConflictingAlertmanagerStorageAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesAlertmanagerStorageFindings(ctx, analysis, a.ID())
}

func (a *KubernetesInvalidAlertmanagerRetentionAnalyzer) ID() string {
	return KubernetesInvalidAlertmanagerRetentionAnalyzerID
}
func (a *KubernetesInvalidAlertmanagerRetentionAnalyzer) Name() string {
	return "Kubernetes Invalid Alertmanager Retention"
}
func (a *KubernetesInvalidAlertmanagerRetentionAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesInvalidAlertmanagerRetentionAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}
func (a *KubernetesInvalidAlertmanagerRetentionAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesAlertmanagerStorageFindings(ctx, analysis, a.ID())
}

func kubernetesAlertmanagerStorageFindings(ctx context.Context, analysis Context, analyzerID string) ([]model.Finding, error) {
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
		finding, matched := kubernetesAlertmanagerStorageFinding(analyzerID, resource, now)
		if matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesAlertmanagerStorageFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityCritical
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "Alertmanager", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesEphemeralAlertmanagerStorageAnalyzerID:
		mode := resource.Metadata["alertmanager_storage_mode"]
		if mode != "default-empty-dir" && mode != "empty-dir" && mode != "ephemeral" {
			return model.Finding{}, false
		}
		replicas := alertmanagerStorageMetadataInt64(resource, "alertmanager_replicas")
		if replicas > 1 {
			severity = model.SeverityWarning
		}
		category = model.FindingCategoryReliability
		findingType = "KubernetesEphemeralAlertmanagerStorage"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q uses %s storage with %d replica(s), so silence and notification state can be lost during Pod or cluster replacement", resource.Name, mode, replicas)
		recommendation = "为生产 Alertmanager 配置 volumeClaimTemplate；HA 副本可降低单 Pod 故障风险，但不能替代持久化存储对整体重建的保护。"
		metadata["alertmanager_storage_mode"] = mode
		metadata["alertmanager_replicas"] = strconv.FormatInt(replicas, 10)
	case KubernetesConflictingAlertmanagerStorageAnalyzerID:
		count := alertmanagerStorageMetadataInt64(resource, "alertmanager_storage_option_count")
		if count <= 1 {
			return model.Finding{}, false
		}
		findingType = "KubernetesConflictingAlertmanagerStorage"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares %d storage options; the Operator applies only one according to precedence", resource.Name, count)
		recommendation = "仅保留 emptyDir、ephemeral 或 volumeClaimTemplate 中的一种，避免清单意图与实际挂载类型不一致。"
		metadata["alertmanager_storage_option_count"] = strconv.FormatInt(count, 10)
	case KubernetesInvalidAlertmanagerRetentionAnalyzerID:
		if resource.Metadata["alertmanager_retention_declared"] != "true" || resource.Metadata["alertmanager_retention_valid"] == "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidAlertmanagerRetention"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares a retention value outside the Operator duration format", resource.Name)
		recommendation = "使用正数和单个 ms、s、m 或 h 单位配置 retention，例如 120h；修复后确认 Operator 已成功调谐。"
		metadata["alertmanager_retention_invalid"] = "true"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}

func alertmanagerStorageMetadataInt64(resource model.Resource, key string) int64 {
	value, err := strconv.ParseInt(strings.TrimSpace(resource.Metadata[key]), 10, 64)
	if err != nil {
		return 0
	}
	return value
}
