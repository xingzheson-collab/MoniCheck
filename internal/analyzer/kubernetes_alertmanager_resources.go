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
	KubernetesInvalidAlertmanagerResourcesAnalyzerID        = "builtin.kubernetes_invalid_alertmanager_resources"
	KubernetesAlertmanagerWithoutResourceRequestsAnalyzerID = "builtin.kubernetes_alertmanager_without_resource_requests"
	KubernetesAlertmanagerWithoutMemoryLimitAnalyzerID      = "builtin.kubernetes_alertmanager_without_memory_limit"
)

type KubernetesAlertmanagerResourcesAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidAlertmanagerResourcesAnalyzer() *KubernetesAlertmanagerResourcesAnalyzer {
	return &KubernetesAlertmanagerResourcesAnalyzer{id: KubernetesInvalidAlertmanagerResourcesAnalyzerID, name: "Kubernetes Invalid Alertmanager Resources"}
}

func NewKubernetesAlertmanagerWithoutResourceRequestsAnalyzer() *KubernetesAlertmanagerResourcesAnalyzer {
	return &KubernetesAlertmanagerResourcesAnalyzer{id: KubernetesAlertmanagerWithoutResourceRequestsAnalyzerID, name: "Kubernetes Alertmanager Without Resource Requests"}
}

func NewKubernetesAlertmanagerWithoutMemoryLimitAnalyzer() *KubernetesAlertmanagerResourcesAnalyzer {
	return &KubernetesAlertmanagerResourcesAnalyzer{id: KubernetesAlertmanagerWithoutMemoryLimitAnalyzerID, name: "Kubernetes Alertmanager Without Memory Limit"}
}

func (a *KubernetesAlertmanagerResourcesAnalyzer) ID() string      { return a.id }
func (a *KubernetesAlertmanagerResourcesAnalyzer) Name() string    { return a.name }
func (a *KubernetesAlertmanagerResourcesAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesAlertmanagerResourcesAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesAlertmanagerResourcesAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "Alertmanager" || resource.Metadata["alertmanager_resource_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesAlertmanagerResourcesFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesAlertmanagerResourcesFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_resource_invalid_setting_count")
	severity := model.SeverityWarning
	category := model.FindingCategoryReliability
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "Alertmanager", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidAlertmanagerResourcesAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidAlertmanagerResources"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares %d invalid resource requirement setting(s)", resource.Name, invalidCount)
		recommendation = "使用合法的 Kubernetes CPU/内存 Quantity，确保 requests 不大于对应 limits，并通过 admission dry-run 验证清单。"
		metadata["alertmanager_resource_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
	case KubernetesAlertmanagerWithoutResourceRequestsAnalyzerID:
		if invalidCount > 0 || (resource.Metadata["alertmanager_cpu_request_positive"] == "true" && resource.Metadata["alertmanager_memory_request_positive"] == "true") {
			return model.Finding{}, false
		}
		findingType = "KubernetesAlertmanagerWithoutResourceRequests"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q has effective CPU request=%t and memory request=%t", resource.Name, resource.Metadata["alertmanager_cpu_request_positive"] == "true", resource.Metadata["alertmanager_memory_request_positive"] == "true")
		recommendation = "根据历史工作集和通知峰值配置正 CPU/内存 requests，使调度器能够预留稳定容量。"
		metadata["alertmanager_cpu_request_positive"] = resource.Metadata["alertmanager_cpu_request_positive"]
		metadata["alertmanager_memory_request_positive"] = resource.Metadata["alertmanager_memory_request_positive"]
	case KubernetesAlertmanagerWithoutMemoryLimitAnalyzerID:
		if invalidCount > 0 || resource.Metadata["alertmanager_memory_limit_positive"] == "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesAlertmanagerWithoutMemoryLimit"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q has no effective positive memory limit", resource.Name)
		recommendation = "根据稳态内存、告警数量和 silence 峰值配置具有安全余量的 memory limit，并监控 OOM 与 working set。"
		metadata["alertmanager_memory_limit_positive"] = resource.Metadata["alertmanager_memory_limit_positive"]
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
