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
	KubernetesInvalidPrometheusStatefulSetStrategyAnalyzerID = "builtin.kubernetes_invalid_prometheus_statefulset_strategy"
	KubernetesPrometheusHAOrderedPodManagementAnalyzerID     = "builtin.kubernetes_prometheus_ha_ordered_pod_management"
	KubernetesPrometheusOnDeleteUpdateAnalyzerID             = "builtin.kubernetes_prometheus_on_delete_update"
	KubernetesPrometheusHighUnavailableUpdateAnalyzerID      = "builtin.kubernetes_prometheus_high_unavailable_update"
)

type KubernetesPrometheusStatefulSetAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidPrometheusStatefulSetStrategyAnalyzer() *KubernetesPrometheusStatefulSetAnalyzer {
	return &KubernetesPrometheusStatefulSetAnalyzer{id: KubernetesInvalidPrometheusStatefulSetStrategyAnalyzerID, name: "Kubernetes Invalid Prometheus StatefulSet Strategy"}
}

func NewKubernetesPrometheusHAOrderedPodManagementAnalyzer() *KubernetesPrometheusStatefulSetAnalyzer {
	return &KubernetesPrometheusStatefulSetAnalyzer{id: KubernetesPrometheusHAOrderedPodManagementAnalyzerID, name: "Kubernetes HA Prometheus Ordered Pod Management"}
}

func NewKubernetesPrometheusOnDeleteUpdateAnalyzer() *KubernetesPrometheusStatefulSetAnalyzer {
	return &KubernetesPrometheusStatefulSetAnalyzer{id: KubernetesPrometheusOnDeleteUpdateAnalyzerID, name: "Kubernetes Prometheus OnDelete Update"}
}

func NewKubernetesPrometheusHighUnavailableUpdateAnalyzer() *KubernetesPrometheusStatefulSetAnalyzer {
	return &KubernetesPrometheusStatefulSetAnalyzer{id: KubernetesPrometheusHighUnavailableUpdateAnalyzerID, name: "Kubernetes Prometheus High Unavailable Update"}
}

func (a *KubernetesPrometheusStatefulSetAnalyzer) ID() string      { return a.id }
func (a *KubernetesPrometheusStatefulSetAnalyzer) Name() string    { return a.name }
func (a *KubernetesPrometheusStatefulSetAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusStatefulSetAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *KubernetesPrometheusStatefulSetAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (resource.Metadata["kubernetes_kind"] != "Prometheus" && resource.Metadata["kubernetes_kind"] != "PrometheusAgent") || resource.Metadata["prometheus_statefulset_metadata"] != "true" || resource.Metadata["prometheus_statefulset_applicable"] != "true" {
			continue
		}
		if finding, matched := kubernetesPrometheusStatefulSetFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesPrometheusStatefulSetFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := prometheusStorageMetadataInt64(resource, "prometheus_update_strategy_invalid_setting_count")
	severity := model.SeverityWarning
	category := model.FindingCategoryReliability
	findingType := ""
	evidence := ""
	recommendation := ""
	kind := resource.Metadata["kubernetes_kind"]
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidPrometheusStatefulSetStrategyAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidPrometheusStatefulSetStrategy"
		evidence = fmt.Sprintf("Kubernetes %s %q declares %d invalid StatefulSet strategy setting(s)", kind, resource.Name, invalidCount)
		recommendation = "使用 Parallel 或 OrderedReady podManagementPolicy，以及合法 RollingUpdate/OnDelete updateStrategy；RollingUpdate maxUnavailable 必须是正整数或 1%-100%。"
		metadata["prometheus_update_strategy_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
	case KubernetesPrometheusHAOrderedPodManagementAnalyzerID:
		if invalidCount > 0 || prometheusStorageMetadataInt64(resource, "prometheus_replicas") < 2 || resource.Metadata["prometheus_pod_management_policy"] != "OrderedReady" {
			return model.Finding{}, false
		}
		findingType = "KubernetesPrometheusHAOrderedPodManagement"
		evidence = fmt.Sprintf("Kubernetes %s %q uses OrderedReady Pod management, allowing one stuck ordinal to block scaling or rollout progress", kind, resource.Name)
		recommendation = "使用 Operator 默认的 Parallel podManagementPolicy，并在变更该字段前规划 StatefulSet 重建和服务连续性。"
		metadata["prometheus_pod_management_policy"] = "OrderedReady"
	case KubernetesPrometheusOnDeleteUpdateAnalyzerID:
		if invalidCount > 0 || resource.Metadata["prometheus_update_strategy_type"] != "OnDelete" {
			return model.Finding{}, false
		}
		category = model.FindingCategoryLifecycle
		findingType = "KubernetesPrometheusOnDeleteUpdate"
		evidence = fmt.Sprintf("Kubernetes %s %q uses OnDelete updates, so Pods keep the old revision until manually deleted", kind, resource.Name)
		recommendation = "改用 RollingUpdate，或为 OnDelete 建立经过验证的逐 Pod 删除、健康检查和版本一致性流程。"
		metadata["prometheus_update_strategy_type"] = "OnDelete"
	case KubernetesPrometheusHighUnavailableUpdateAnalyzerID:
		effective := prometheusStorageMetadataInt64(resource, "prometheus_effective_max_unavailable")
		if invalidCount > 0 || resource.Metadata["prometheus_update_strategy_type"] != "RollingUpdate" || resource.Metadata["prometheus_max_unavailable_valid"] != "true" || effective <= 1 {
			return model.Finding{}, false
		}
		findingType = "KubernetesPrometheusHighUnavailableUpdate"
		evidence = fmt.Sprintf("Kubernetes %s %q permits up to %d unavailable Pods per shard during a rolling update", kind, resource.Name, effective)
		recommendation = "将 rollingUpdate.maxUnavailable 收紧到 1，避免滚动升级同时降低多个采集或查询副本的可用容量。"
		metadata["prometheus_effective_max_unavailable"] = fmt.Sprintf("%d", effective)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
