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
	KubernetesInvalidAlertmanagerPlacementAnalyzerID              = "builtin.kubernetes_invalid_alertmanager_placement"
	KubernetesAlertmanagerBroadTolerationAnalyzerID               = "builtin.kubernetes_alertmanager_broad_toleration"
	KubernetesAlertmanagerIndefiniteNoExecuteTolerationAnalyzerID = "builtin.kubernetes_alertmanager_indefinite_no_execute_toleration"
	KubernetesAlertmanagerCustomSchedulerAnalyzerID               = "builtin.kubernetes_alertmanager_custom_scheduler"
)

type KubernetesAlertmanagerPlacementAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidAlertmanagerPlacementAnalyzer() *KubernetesAlertmanagerPlacementAnalyzer {
	return &KubernetesAlertmanagerPlacementAnalyzer{id: KubernetesInvalidAlertmanagerPlacementAnalyzerID, name: "Kubernetes Invalid Alertmanager Placement"}
}

func NewKubernetesAlertmanagerBroadTolerationAnalyzer() *KubernetesAlertmanagerPlacementAnalyzer {
	return &KubernetesAlertmanagerPlacementAnalyzer{id: KubernetesAlertmanagerBroadTolerationAnalyzerID, name: "Kubernetes Alertmanager Broad Toleration"}
}

func NewKubernetesAlertmanagerIndefiniteNoExecuteTolerationAnalyzer() *KubernetesAlertmanagerPlacementAnalyzer {
	return &KubernetesAlertmanagerPlacementAnalyzer{id: KubernetesAlertmanagerIndefiniteNoExecuteTolerationAnalyzerID, name: "Kubernetes Alertmanager Indefinite NoExecute Toleration"}
}

func NewKubernetesAlertmanagerCustomSchedulerAnalyzer() *KubernetesAlertmanagerPlacementAnalyzer {
	return &KubernetesAlertmanagerPlacementAnalyzer{id: KubernetesAlertmanagerCustomSchedulerAnalyzerID, name: "Kubernetes Alertmanager Custom Scheduler"}
}

func (a *KubernetesAlertmanagerPlacementAnalyzer) ID() string      { return a.id }
func (a *KubernetesAlertmanagerPlacementAnalyzer) Name() string    { return a.name }
func (a *KubernetesAlertmanagerPlacementAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesAlertmanagerPlacementAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesAlertmanagerPlacementAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "Alertmanager" || resource.Metadata["alertmanager_placement_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesAlertmanagerPlacementFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesAlertmanagerPlacementFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	tolerationInvalidCount := alertmanagerStorageMetadataInt64(resource, "alertmanager_toleration_invalid_setting_count")
	nodeSelectorInvalid := resource.Metadata["alertmanager_node_selector_declared"] == "true" && resource.Metadata["alertmanager_node_selector_valid"] != "true"
	schedulerInvalid := resource.Metadata["alertmanager_scheduler_name_declared"] == "true" && resource.Metadata["alertmanager_scheduler_name_valid"] != "true"
	priorityClassInvalid := resource.Metadata["alertmanager_priority_class_name_declared"] == "true" && resource.Metadata["alertmanager_priority_class_name_valid"] != "true"
	findingType := ""
	evidence := ""
	recommendation := ""
	severity := model.SeverityWarning
	category := model.FindingCategoryReliability
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "Alertmanager", "namespace": kubernetesResourceNamespace(resource)}
	switch analyzerID {
	case KubernetesInvalidAlertmanagerPlacementAnalyzerID:
		if !nodeSelectorInvalid && !schedulerInvalid && !priorityClassInvalid && tolerationInvalidCount == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryConfiguration
		findingType = "KubernetesInvalidAlertmanagerPlacement"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q has invalid placement settings: nodeSelector invalid=%t, schedulerName invalid=%t, priorityClassName invalid=%t, toleration settings invalid=%d", resource.Name, nodeSelectorInvalid, schedulerInvalid, priorityClassInvalid, tolerationInvalidCount)
		recommendation = "使用合法 Kubernetes nodeSelector 标签、非空 schedulerName/priorityClassName，并按 key/operator/value/effect/tolerationSeconds 约束修正 tolerations。"
		metadata["alertmanager_node_selector_invalid"] = fmt.Sprintf("%t", nodeSelectorInvalid)
		metadata["alertmanager_scheduler_name_invalid"] = fmt.Sprintf("%t", schedulerInvalid)
		metadata["alertmanager_priority_class_name_invalid"] = fmt.Sprintf("%t", priorityClassInvalid)
		metadata["alertmanager_toleration_invalid_setting_count"] = fmt.Sprintf("%d", tolerationInvalidCount)
	case KubernetesAlertmanagerBroadTolerationAnalyzerID:
		count := alertmanagerStorageMetadataInt64(resource, "alertmanager_broad_toleration_count")
		if tolerationInvalidCount > 0 || count == 0 {
			return model.Finding{}, false
		}
		category = model.FindingCategorySecurity
		findingType = "KubernetesAlertmanagerBroadToleration"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares %d toleration(s) with an empty key and Exists operator, matching every taint key for the selected effect", resource.Name, count)
		recommendation = "将 toleration 限定到明确的 taint key、effect 和必要 value，并配合 nodeSelector 或 required node affinity 约束到预期节点池。"
		metadata["alertmanager_broad_toleration_count"] = fmt.Sprintf("%d", count)
	case KubernetesAlertmanagerIndefiniteNoExecuteTolerationAnalyzerID:
		count := alertmanagerStorageMetadataInt64(resource, "alertmanager_indefinite_no_execute_toleration_count")
		if tolerationInvalidCount > 0 || count == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesAlertmanagerIndefiniteNoExecuteToleration"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q declares %d NoExecute-capable toleration(s) without tolerationSeconds, allowing Pods to remain bound indefinitely", resource.Name, count)
		recommendation = "为 NoExecute toleration 设置符合恢复目标的有限 tolerationSeconds；仅对经过验证且应永久驻留的专用节点场景保留无限容忍。"
		metadata["alertmanager_indefinite_no_execute_toleration_count"] = fmt.Sprintf("%d", count)
	case KubernetesAlertmanagerCustomSchedulerAnalyzerID:
		if resource.Metadata["alertmanager_scheduler_name_valid"] != "true" || resource.Metadata["alertmanager_custom_scheduler"] != "true" {
			return model.Finding{}, false
		}
		findingType = "KubernetesAlertmanagerCustomScheduler"
		evidence = fmt.Sprintf("Kubernetes Alertmanager %q delegates Pod placement to an explicit non-default scheduler", resource.Name)
		recommendation = "确认自定义 scheduler 高可用、升级兼容、调度失败告警和回退到 default-scheduler 的流程，并验证其遵守资源、亲和性、污点及拓扑约束。"
		metadata["alertmanager_custom_scheduler"] = "true"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
