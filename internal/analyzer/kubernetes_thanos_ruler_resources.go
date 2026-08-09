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
	KubernetesInvalidThanosRulerResourcesAnalyzerID        = "builtin.kubernetes_invalid_thanos_ruler_resources"
	KubernetesThanosRulerWithoutResourceRequestsAnalyzerID = "builtin.kubernetes_thanos_ruler_without_resource_requests"
	KubernetesThanosRulerWithoutMemoryLimitAnalyzerID      = "builtin.kubernetes_thanos_ruler_without_memory_limit"
)

type KubernetesThanosRulerResourcesAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidThanosRulerResourcesAnalyzer() *KubernetesThanosRulerResourcesAnalyzer {
	return &KubernetesThanosRulerResourcesAnalyzer{id: KubernetesInvalidThanosRulerResourcesAnalyzerID, name: "Kubernetes Invalid ThanosRuler Resources"}
}

func NewKubernetesThanosRulerWithoutResourceRequestsAnalyzer() *KubernetesThanosRulerResourcesAnalyzer {
	return &KubernetesThanosRulerResourcesAnalyzer{id: KubernetesThanosRulerWithoutResourceRequestsAnalyzerID, name: "Kubernetes ThanosRuler Without Resource Requests"}
}

func NewKubernetesThanosRulerWithoutMemoryLimitAnalyzer() *KubernetesThanosRulerResourcesAnalyzer {
	return &KubernetesThanosRulerResourcesAnalyzer{id: KubernetesThanosRulerWithoutMemoryLimitAnalyzerID, name: "Kubernetes ThanosRuler Without Memory Limit"}
}

func (a *KubernetesThanosRulerResourcesAnalyzer) ID() string      { return a.id }
func (a *KubernetesThanosRulerResourcesAnalyzer) Name() string    { return a.name }
func (a *KubernetesThanosRulerResourcesAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerResourcesAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesThanosRulerResourcesAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" || resource.Metadata["thanos_ruler_resource_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesThanosRulerResourcesFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesThanosRulerResourcesFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_resource_invalid_setting_count")
	severity := model.SeverityWarning
	category := model.FindingCategoryReliability
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ThanosRuler", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidThanosRulerResourcesAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidThanosRulerResources"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares %d invalid primary-container resource requirement setting(s)", resource.Name, invalidCount)
		recommendation = "使用合法的 Kubernetes CPU/内存 Quantity，确保 requests 不大于对应 limits，并通过 admission dry-run 验证清单。"
		metadata["thanos_ruler_resource_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
	case KubernetesThanosRulerWithoutResourceRequestsAnalyzerID:
		if invalidCount > 0 || (resource.Metadata["thanos_ruler_cpu_request_positive"] == "true" && resource.Metadata["thanos_ruler_memory_request_positive"] == "true") {
			return model.Finding{}, false
		}
		findingType = "KubernetesThanosRulerWithoutResourceRequests"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q primary container has effective CPU request=%t and memory request=%t", resource.Name, resource.Metadata["thanos_ruler_cpu_request_positive"] == "true", resource.Metadata["thanos_ruler_memory_request_positive"] == "true")
		recommendation = "根据规则数量、查询负载和历史 working set 配置正 CPU/内存 requests，使调度器为规则计算预留稳定容量。"
		metadata["thanos_ruler_cpu_request_positive"] = resource.Metadata["thanos_ruler_cpu_request_positive"]
		metadata["thanos_ruler_memory_request_positive"] = resource.Metadata["thanos_ruler_memory_request_positive"]
	case KubernetesThanosRulerWithoutMemoryLimitAnalyzerID:
		if invalidCount > 0 || resource.Metadata["thanos_ruler_memory_limit_positive"] == "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesThanosRulerWithoutMemoryLimit"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q primary container has no effective positive memory limit", resource.Name)
		recommendation = "根据规则评估并发、查询结果规模和历史 working set 配置具有安全余量的 memory limit，并监控 OOM、GC 和内存饱和度。"
		metadata["thanos_ruler_memory_limit_positive"] = resource.Metadata["thanos_ruler_memory_limit_positive"]
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
