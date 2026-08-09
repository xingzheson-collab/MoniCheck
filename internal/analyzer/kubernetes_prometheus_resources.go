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
	KubernetesInvalidPrometheusResourcesAnalyzerID        = "builtin.kubernetes_invalid_prometheus_resources"
	KubernetesPrometheusWithoutResourceRequestsAnalyzerID = "builtin.kubernetes_prometheus_without_resource_requests"
	KubernetesPrometheusWithoutMemoryLimitAnalyzerID      = "builtin.kubernetes_prometheus_without_memory_limit"
)

type KubernetesPrometheusResourcesAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidPrometheusResourcesAnalyzer() *KubernetesPrometheusResourcesAnalyzer {
	return &KubernetesPrometheusResourcesAnalyzer{id: KubernetesInvalidPrometheusResourcesAnalyzerID, name: "Kubernetes Invalid Prometheus Resources"}
}

func NewKubernetesPrometheusWithoutResourceRequestsAnalyzer() *KubernetesPrometheusResourcesAnalyzer {
	return &KubernetesPrometheusResourcesAnalyzer{id: KubernetesPrometheusWithoutResourceRequestsAnalyzerID, name: "Kubernetes Prometheus Without Resource Requests"}
}

func NewKubernetesPrometheusWithoutMemoryLimitAnalyzer() *KubernetesPrometheusResourcesAnalyzer {
	return &KubernetesPrometheusResourcesAnalyzer{id: KubernetesPrometheusWithoutMemoryLimitAnalyzerID, name: "Kubernetes Prometheus Without Memory Limit"}
}

func (a *KubernetesPrometheusResourcesAnalyzer) ID() string      { return a.id }
func (a *KubernetesPrometheusResourcesAnalyzer) Name() string    { return a.name }
func (a *KubernetesPrometheusResourcesAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusResourcesAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *KubernetesPrometheusResourcesAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := resource.Metadata["kubernetes_kind"]
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "Prometheus" && kind != "PrometheusAgent") || resource.Metadata["prometheus_resource_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesPrometheusResourcesFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesPrometheusResourcesFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := alertmanagerStorageMetadataInt64(resource, "prometheus_resource_invalid_setting_count")
	severity := model.SeverityWarning
	category := model.FindingCategoryReliability
	findingType := ""
	evidence := ""
	recommendation := ""
	kind := resource.Metadata["kubernetes_kind"]
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidPrometheusResourcesAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidPrometheusResources"
		evidence = fmt.Sprintf("Kubernetes %s %q declares %d invalid primary-container resource requirement setting(s)", kind, resource.Name, invalidCount)
		recommendation = "使用合法的 Kubernetes CPU/内存 Quantity，确保 requests 不大于对应 limits，并通过 admission dry-run 验证清单。"
		metadata["prometheus_resource_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
	case KubernetesPrometheusWithoutResourceRequestsAnalyzerID:
		if invalidCount > 0 || (resource.Metadata["prometheus_cpu_request_positive"] == "true" && resource.Metadata["prometheus_memory_request_positive"] == "true") {
			return model.Finding{}, false
		}
		findingType = "KubernetesPrometheusWithoutResourceRequests"
		evidence = fmt.Sprintf("Kubernetes %s %q primary container has effective CPU request=%t and memory request=%t", kind, resource.Name, resource.Metadata["prometheus_cpu_request_positive"] == "true", resource.Metadata["prometheus_memory_request_positive"] == "true")
		recommendation = "根据活跃序列、查询负载、采集峰值和历史 working set 配置正 CPU/内存 requests，使调度器预留稳定容量。"
		metadata["prometheus_cpu_request_positive"] = resource.Metadata["prometheus_cpu_request_positive"]
		metadata["prometheus_memory_request_positive"] = resource.Metadata["prometheus_memory_request_positive"]
	case KubernetesPrometheusWithoutMemoryLimitAnalyzerID:
		if invalidCount > 0 || resource.Metadata["prometheus_memory_limit_positive"] == "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesPrometheusWithoutMemoryLimit"
		evidence = fmt.Sprintf("Kubernetes %s %q primary container has no effective positive memory limit", kind, resource.Name)
		recommendation = "根据 TSDB working set、查询峰值和 ingestion headroom 配置具有安全余量的 memory limit，并监控 OOM、GC 和内存饱和度。"
		metadata["prometheus_memory_limit_positive"] = resource.Metadata["prometheus_memory_limit_positive"]
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
