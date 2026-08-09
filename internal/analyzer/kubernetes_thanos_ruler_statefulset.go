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
	KubernetesInvalidThanosRulerStatefulSetStrategyAnalyzerID = "builtin.kubernetes_invalid_thanos_ruler_statefulset_strategy"
	KubernetesThanosRulerHAOrderedPodManagementAnalyzerID     = "builtin.kubernetes_thanos_ruler_ha_ordered_pod_management"
	KubernetesThanosRulerOnDeleteUpdateAnalyzerID             = "builtin.kubernetes_thanos_ruler_on_delete_update"
	KubernetesThanosRulerHighUnavailableUpdateAnalyzerID      = "builtin.kubernetes_thanos_ruler_high_unavailable_update"
)

type KubernetesThanosRulerStatefulSetAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidThanosRulerStatefulSetStrategyAnalyzer() *KubernetesThanosRulerStatefulSetAnalyzer {
	return &KubernetesThanosRulerStatefulSetAnalyzer{id: KubernetesInvalidThanosRulerStatefulSetStrategyAnalyzerID, name: "Kubernetes Invalid ThanosRuler StatefulSet Strategy"}
}
func NewKubernetesThanosRulerHAOrderedPodManagementAnalyzer() *KubernetesThanosRulerStatefulSetAnalyzer {
	return &KubernetesThanosRulerStatefulSetAnalyzer{id: KubernetesThanosRulerHAOrderedPodManagementAnalyzerID, name: "Kubernetes HA ThanosRuler Ordered Pod Management"}
}
func NewKubernetesThanosRulerOnDeleteUpdateAnalyzer() *KubernetesThanosRulerStatefulSetAnalyzer {
	return &KubernetesThanosRulerStatefulSetAnalyzer{id: KubernetesThanosRulerOnDeleteUpdateAnalyzerID, name: "Kubernetes ThanosRuler OnDelete Update"}
}
func NewKubernetesThanosRulerHighUnavailableUpdateAnalyzer() *KubernetesThanosRulerStatefulSetAnalyzer {
	return &KubernetesThanosRulerStatefulSetAnalyzer{id: KubernetesThanosRulerHighUnavailableUpdateAnalyzerID, name: "Kubernetes ThanosRuler High Unavailable Update"}
}

func (a *KubernetesThanosRulerStatefulSetAnalyzer) ID() string      { return a.id }
func (a *KubernetesThanosRulerStatefulSetAnalyzer) Name() string    { return a.name }
func (a *KubernetesThanosRulerStatefulSetAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerStatefulSetAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesThanosRulerStatefulSetAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" || resource.Metadata["thanos_ruler_statefulset_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesThanosRulerStatefulSetFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesThanosRulerStatefulSetFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_update_strategy_invalid_setting_count")
	severity := model.SeverityWarning
	category := model.FindingCategoryReliability
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ThanosRuler", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidThanosRulerStatefulSetStrategyAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidThanosRulerStatefulSetStrategy"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares %d invalid StatefulSet strategy setting(s)", resource.Name, invalidCount)
		recommendation = "使用 Parallel 或 OrderedReady podManagementPolicy，以及合法 RollingUpdate/OnDelete updateStrategy；maxUnavailable 必须是正整数或 1%-100%。"
		metadata["thanos_ruler_update_strategy_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
	case KubernetesThanosRulerHAOrderedPodManagementAnalyzerID:
		if invalidCount > 0 || alertmanagerStorageMetadataInt64(resource, "thanos_ruler_replicas") < 2 || resource.Metadata["thanos_ruler_pod_management_policy"] != "OrderedReady" {
			return model.Finding{}, false
		}
		findingType = "KubernetesThanosRulerHAOrderedPodManagement"
		evidence = fmt.Sprintf("Kubernetes HA ThanosRuler %q uses OrderedReady Pod management, allowing one stuck ordinal to block scaling or rollout progress", resource.Name)
		recommendation = "使用 Operator 默认的 Parallel podManagementPolicy，并在变更该字段前规划 StatefulSet 重建和服务连续性。"
		metadata["thanos_ruler_pod_management_policy"] = "OrderedReady"
	case KubernetesThanosRulerOnDeleteUpdateAnalyzerID:
		if invalidCount > 0 || resource.Metadata["thanos_ruler_update_strategy_type"] != "OnDelete" {
			return model.Finding{}, false
		}
		category = model.FindingCategoryLifecycle
		findingType = "KubernetesThanosRulerOnDeleteUpdate"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q uses OnDelete updates, so Pods keep the old revision until manually deleted", resource.Name)
		recommendation = "改用 RollingUpdate，或为 OnDelete 建立经过验证的逐 Pod 删除、规则评估健康检查和版本一致性流程。"
		metadata["thanos_ruler_update_strategy_type"] = "OnDelete"
	case KubernetesThanosRulerHighUnavailableUpdateAnalyzerID:
		effective := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_effective_max_unavailable")
		if invalidCount > 0 || resource.Metadata["thanos_ruler_update_strategy_type"] != "RollingUpdate" || resource.Metadata["thanos_ruler_max_unavailable_valid"] != "true" || effective <= 1 {
			return model.Finding{}, false
		}
		findingType = "KubernetesThanosRulerHighUnavailableUpdate"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q permits up to %d unavailable Pods during a rolling update", resource.Name, effective)
		recommendation = "将 rollingUpdate.maxUnavailable 收紧到 1，避免升级同时降低多个规则执行副本的可用容量。"
		metadata["thanos_ruler_effective_max_unavailable"] = fmt.Sprintf("%d", effective)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
