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
	KubernetesInvalidAlertmanagerStatefulSetStrategyAnalyzerID = "builtin.kubernetes_invalid_alertmanager_statefulset_strategy"
	KubernetesAlertmanagerHAOrderedPodManagementAnalyzerID     = "builtin.kubernetes_alertmanager_ha_ordered_pod_management"
	KubernetesAlertmanagerOnDeleteUpdateAnalyzerID             = "builtin.kubernetes_alertmanager_on_delete_update"
	KubernetesAlertmanagerHighUnavailableUpdateAnalyzerID      = "builtin.kubernetes_alertmanager_high_unavailable_update"
)

type KubernetesAlertmanagerStatefulSetAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidAlertmanagerStatefulSetStrategyAnalyzer() *KubernetesAlertmanagerStatefulSetAnalyzer {
	return &KubernetesAlertmanagerStatefulSetAnalyzer{id: KubernetesInvalidAlertmanagerStatefulSetStrategyAnalyzerID, name: "Kubernetes Invalid Alertmanager StatefulSet Strategy"}
}

func NewKubernetesAlertmanagerHAOrderedPodManagementAnalyzer() *KubernetesAlertmanagerStatefulSetAnalyzer {
	return &KubernetesAlertmanagerStatefulSetAnalyzer{id: KubernetesAlertmanagerHAOrderedPodManagementAnalyzerID, name: "Kubernetes HA Alertmanager Ordered Pod Management"}
}

func NewKubernetesAlertmanagerOnDeleteUpdateAnalyzer() *KubernetesAlertmanagerStatefulSetAnalyzer {
	return &KubernetesAlertmanagerStatefulSetAnalyzer{id: KubernetesAlertmanagerOnDeleteUpdateAnalyzerID, name: "Kubernetes Alertmanager OnDelete Update"}
}

func NewKubernetesAlertmanagerHighUnavailableUpdateAnalyzer() *KubernetesAlertmanagerStatefulSetAnalyzer {
	return &KubernetesAlertmanagerStatefulSetAnalyzer{id: KubernetesAlertmanagerHighUnavailableUpdateAnalyzerID, name: "Kubernetes Alertmanager High Unavailable Update"}
}

func (a *KubernetesAlertmanagerStatefulSetAnalyzer) ID() string      { return a.id }
func (a *KubernetesAlertmanagerStatefulSetAnalyzer) Name() string    { return a.name }
func (a *KubernetesAlertmanagerStatefulSetAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesAlertmanagerStatefulSetAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesAlertmanagerStatefulSetAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "Alertmanager" || resource.Metadata["alertmanager_statefulset_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesAlertmanagerStatefulSetFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesAlertmanagerStatefulSetFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	invalidCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_update_strategy_invalid_setting_count")
	severity := model.SeverityWarning
	category := model.FindingCategoryReliability
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "Alertmanager", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidAlertmanagerStatefulSetStrategyAnalyzerID:
		if invalidCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidAlertmanagerStatefulSetStrategy"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares %d invalid StatefulSet strategy setting(s)", resource.Name, invalidCount)
		recommendation = "使用 Parallel 或 OrderedReady podManagementPolicy，以及合法 RollingUpdate/OnDelete updateStrategy；RollingUpdate maxUnavailable 必须是正整数或 1%-100%。"
		metadata["alertmanager_update_strategy_invalid_setting_count"] = fmt.Sprintf("%d", invalidCount)
	case KubernetesAlertmanagerHAOrderedPodManagementAnalyzerID:
		if invalidCount > 0 || alertmanagerStorageMetadataInt64(resource, "alertmanager_replicas") < 2 || resource.Metadata["alertmanager_pod_management_policy"] != "OrderedReady" {
			return model.Finding{}, false
		}
		findingType = "KubernetesAlertmanagerHAOrderedPodManagement"
		evidence = fmt.Sprintf("Kubernetes HA Alertmanager %q uses OrderedReady Pod management, allowing one stuck ordinal to block scaling or rollout progress", resource.Name)
		recommendation = "使用 Operator 默认的 Parallel podManagementPolicy，并在变更该字段前规划 StatefulSet 重建和服务连续性。"
		metadata["alertmanager_pod_management_policy"] = "OrderedReady"
	case KubernetesAlertmanagerOnDeleteUpdateAnalyzerID:
		if invalidCount > 0 || resource.Metadata["alertmanager_update_strategy_type"] != "OnDelete" {
			return model.Finding{}, false
		}
		category = model.FindingCategoryLifecycle
		findingType = "KubernetesAlertmanagerOnDeleteUpdate"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q uses OnDelete updates, so Pods keep the old revision until manually deleted", resource.Name)
		recommendation = "改用 RollingUpdate，或为 OnDelete 建立经过验证的逐 Pod 删除、健康检查和版本一致性流程。"
		metadata["alertmanager_update_strategy_type"] = "OnDelete"
	case KubernetesAlertmanagerHighUnavailableUpdateAnalyzerID:
		effective := alertmanagerStorageMetadataInt64(resource, "alertmanager_effective_max_unavailable")
		if invalidCount > 0 || resource.Metadata["alertmanager_update_strategy_type"] != "RollingUpdate" || resource.Metadata["alertmanager_max_unavailable_valid"] != "true" || effective <= 1 {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "KubernetesAlertmanagerHighUnavailableUpdate"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q permits up to %d unavailable Pods during a rolling update", resource.Name, effective)
		recommendation = "将 rollingUpdate.maxUnavailable 收紧到 1，避免滚动升级同时降低多个 Alertmanager 副本的通知容量和集群仲裁余量。"
		metadata["alertmanager_effective_max_unavailable"] = fmt.Sprintf("%d", effective)
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
